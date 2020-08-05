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

/*8198F DPK ver:0xe 20190312*/

void _backup_mac_bb_registers_8198f(
	struct dm_struct *dm,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)
{
	u32 i;

	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = odm_read_4byte(dm, reg[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup MAC/BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _backup_rf_registers_8198f(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 rf_reg_backup[][4])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8198F; i++) {
		rf_reg_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A,
			rf_reg[i], RFREG_MASK);
		rf_reg_backup[i][RF_PATH_B] = odm_get_rf_reg(dm, RF_PATH_B,
			rf_reg[i], RFREG_MASK);
		rf_reg_backup[i][RF_PATH_C] = odm_get_rf_reg(dm, RF_PATH_C,
			rf_reg[i], RFREG_MASK);
		rf_reg_backup[i][RF_PATH_D] = odm_get_rf_reg(dm, RF_PATH_D,
			rf_reg[i], RFREG_MASK);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_B 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_B]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_C 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_C]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_D 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_D]);
#endif
	}
}

void _reload_mac_bb_registers_8198f(
	struct dm_struct *dm,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)

{
	u32 i;

	for (i = 0; i < reg_num; i++) {
		odm_write_4byte(dm, reg[i], reg_backup[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload MAC/BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _reload_rf_registers_8198f(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 rf_reg_backup[][4])
{
	u32 i, rf_reg_8f[DPK_RF_PATH_NUM_8198F] = {0x0};

	for (i = 0; i < DPK_RF_REG_NUM_8198F; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_A]);
		odm_set_rf_reg(dm, RF_PATH_B, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_B]);
		odm_set_rf_reg(dm, RF_PATH_C, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_C]);
		odm_set_rf_reg(dm, RF_PATH_D, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_D]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_B 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_B]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_C 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_C]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_D 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_D]);
#endif
	}
	/*reload RF 0x8f for non-saving power mode*/
	for (i = 0; i < DPK_RF_PATH_NUM_8198F; i++) {
		rf_reg_8f[i] = odm_get_rf_reg(dm, (enum rf_path)i,
			RF_0x8f, 0x00fff);
		odm_set_rf_reg(dm, (enum rf_path)i, RF_0x8f, RFREG_MASK,
			       0xa8000 | rf_reg_8f[i]);
	}
}

void _dpk_information_8198f(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u32  reg_rf18;

	reg_rf18 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK);

	dpk_info->dpk_ch = (u8)reg_rf18 & 0xff;
	dpk_info->dpk_bw = (u8)((reg_rf18 & 0x3000) >> 12); /*3/2:20/40*/

	RF_DBG(dm, DBG_RF_DPK, "[DPK] CH / BW = %d / %s\n",
	       dpk_info->dpk_ch, dpk_info->dpk_bw == 3 ? "20M" : "40M");
}

void _dpk_mode_8198f(
	struct dm_struct *dm,
	boolean is_dpkmode)
{
	/*RF & page 1b can't be write in iqk mode*/
	if (is_dpkmode)
		odm_set_bb_reg(dm, R_0x1cd0, BIT(31), 0x1);
	else
		odm_set_bb_reg(dm, R_0x1cd0, BIT(31), 0x0);
}

void _dpk_clear_even_odd_8198f(
	struct dm_struct *dm)
{
	u8 i;
	u32 reg_1bdc;

	/*clear even*/
	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xd0000000 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}
	/*clear odd*/
	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x90000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}

	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
}

void _dpk_mac_bb_setting_8198f(
	struct dm_struct *dm)
{
	//odm_write_1byte(dm, R_0x522, 0x7f);
	//odm_set_bb_reg(dm, R_0x550, BIT(11) | BIT(3), 0x0);

	/*BB CCA off*/
	odm_set_bb_reg(dm, R_0x1c68,
		       BIT(27) | BIT(26) | BIT(25) | BIT(24), 0xf);
	/*DAC to IQK/PDK*/
	odm_set_bb_reg(dm, R_0x1e24, BIT(17), 0x1);
	odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x1);
	odm_set_bb_reg(dm, R_0x1ca4, BIT(0), 0x1);
	/*enable IQK/PDK loop back in BB*/
	odm_set_bb_reg(dm, R_0x1d60, BIT(31), 0x1);
	odm_set_bb_reg(dm, R_0x1c3c, BIT(1), 0x0); /*disable CCK*/

	/*BB TX path*/
	/*odm_write_4byte(dm, R_0x820, 0xffffffff);*/
	/*odm_set_bb_reg(dm, R_0x824, 0xf0000, 0xf);*/

	RF_DBG(dm, DBG_RF_DPK, "[DPK] MAC/BB setting for DPK mode\n");
}

void _dpk_manual_txagc_8198f(
	struct dm_struct *dm,
	boolean is_manual)
{
	odm_set_bb_reg(dm, R_0x18a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x41a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x52a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x53a4, BIT(7), is_manual);
}

void _dpk_afe_setting_8198f(
	struct dm_struct *dm,
	boolean is_do_dpk)
{
	if (is_do_dpk) {
		/*ADDA FIFO reset on*/
		odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xffffffff);

		/*ADDA all on*/
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x701f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x702f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x704f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x705f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x706f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x707f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x708f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x709f0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70af0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70bf0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70cf0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70df0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ef0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x701f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x702f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x704f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x705f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x706f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x707f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x708f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x709f0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70af0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70bf0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70cf0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70df0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ef0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x701f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x702f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x704f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x705f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x706f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x707f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x708f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x709f0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70af0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70bf0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70cf0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70df0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70ef0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x700f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x701f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x702f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x704f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x705f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x706f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x707f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x708f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x709f0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70af0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70bf0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70cf0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70df0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70ef0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70ff0041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70ff0041);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] AFE setting for DPK mode\n");
	} else {
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x5230, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70fb8041);
		odm_set_bb_reg(dm, R_0x5330, MASKDWORD, 0x70fb8041);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] AFE setting for Normal mode\n");
	}
}

u8 _dpk_rf_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	s8 txidx_offset = 0x0;

	if (path == RF_PATH_A)
		txidx_offset = (u8)odm_get_bb_reg(dm, R_0x18a0, 0x0000007F);
	else if (path == RF_PATH_B)
		txidx_offset = (u8)odm_get_bb_reg(dm, R_0x41a0, 0x0000007F);
	else if (path == RF_PATH_C)
		txidx_offset = (u8)odm_get_bb_reg(dm, R_0x52a0, 0x0000007F);
	else if (path == RF_PATH_D)
		txidx_offset = (u8)odm_get_bb_reg(dm, R_0x53a0, 0x0000007F);

	if ((txidx_offset >> 6) == 1)
		txidx_offset = (txidx_offset - 0x80) / 4;
	else 
		txidx_offset = txidx_offset / 4;

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][GL] S%d txidx_offset = %d\n", path, txidx_offset);

	/*TXAGC for gainloss*/
	if (dm->package_type == 2) /*FB*/
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x00, RFREG_MASK, 0x5001d + txidx_offset);
	else
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x00, RFREG_MASK, 0x5001c + txidx_offset);

	if (dm->cut_version == 0) {
		/*86[3]=1 EN_ATT, 86[2]=0 SWAP_PN, 86[15]=0 PN_SHORT*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x86, RFREG_MASK, 0xa33a9);
		/*8F[14:12] PGA GAIN*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, RFREG_MASK, 0xae2d8);
	} else {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x86, BIT(3), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x86, BIT(2), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x00006000, 0x1);
		/*coupler GAIN*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, BIT(12), 0x1);
		/*TIA GAIN*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x82, BIT(6), 0x0);
	}

	return odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f);
}

void _dpk_pre_setting_8198f(
	struct dm_struct *dm)
{
	u8 path;

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {

		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));

		/*odm_set_bb_reg(dm, R_0x1bc8, MASKDWORD, 0x000c44aa);*/
		odm_set_bb_reg(dm, R_0x1bc8, BIT(19) | BIT(18), 0x3);

		/*dB sel [15:13], 1.5dB=0x1, 2dB=0x2*/
		odm_set_bb_reg(dm, R_0x1b8c, MASKDWORD, 0xFCFF4C20);

		/*tx amp*/
		odm_set_bb_reg(dm, R_0x1b98, MASKDWORD, 0x41382e21);
		odm_set_bb_reg(dm, R_0x1b9c, MASKDWORD, 0x5b554f48);
		odm_set_bb_reg(dm, R_0x1ba0, MASKDWORD, 0x6f6b6661);
		odm_set_bb_reg(dm, R_0x1ba4, MASKDWORD, 0x817d7874);
		odm_set_bb_reg(dm, R_0x1ba8, MASKDWORD, 0x908c8884);
		odm_set_bb_reg(dm, R_0x1bac, MASKDWORD, 0x9d9a9793);
		odm_set_bb_reg(dm, R_0x1bb0, MASKDWORD, 0xaaa7a4a1);
		odm_set_bb_reg(dm, R_0x1bb4, MASKDWORD, 0xb6b3b0ad);
	}
}

void _dpk_con_tx_8198f(
	struct dm_struct *dm,
	boolean is_contx)
{
	if (is_contx) {
		/*block ODFM signal due to contx to observe ramp siganl*/
		odm_set_bb_reg(dm, R_0x800, BIT(31), 0x1);
		odm_set_bb_reg(dm, R_0x1d08, BIT(0), 0x1);
		odm_set_bb_reg(dm, R_0x1ca4, BIT(0), 0x1);
		odm_set_bb_reg(dm, R_0x1e70, BIT(1), 0x1);
		odm_set_bb_reg(dm, R_0x1e70, BIT(1), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x1);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK con_tx on!!!\n");
	} else {
		/*restore ODFM signal*/
		odm_set_bb_reg(dm, R_0x800, BIT(31), 0x0);
		odm_set_bb_reg(dm, R_0x1d08, BIT(0), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x1ca4, BIT(0), 0x0);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK con_tx off!!!\n");
	}
}

void _dpk_bb_path_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	/*_dpk_con_tx_8198f(dm, false);*/

	odm_write_4byte(dm, R_0x820, 0x11111111 * BIT(path));
	odm_set_bb_reg(dm, R_0x824, 0xf0000, 0x1 * BIT(path));
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d 0x820=0x%x, 0x824=0x%x\n", path,
	       odm_get_bb_reg(dm, R_0x820, MASKDWORD),
	       odm_get_bb_reg(dm, R_0x824, MASKDWORD));
#endif
	/*_dpk_con_tx_8198f(dm, true);*/
}

void _dpk_set_group_8198f(
	struct dm_struct *dm,
	u8 group)
{
	switch (group) {
	case 0: /*channel 3*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, 0x07fff, 0x3c03);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to 20M-CH7!!!!\n");*/
		break;

	case 1: /*channel 7*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, 0x07fff, 0x3c07);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to 20M-CH7!!!!\n");*/
		break;

	case 2: /*channel 11*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, 0x07fff, 0x3c0b);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to 20M-CH11!!!!\n");*/
		break;
	}
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to group%d, RF0x18 = 0x%x\n",
	       group, odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK));
#endif
}

void _dpk_one_shot_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 action)
{
	u8 temp = 0x0;
	u16 dpk_cmd = 0x0;

	temp = (1 << (path + 4)) | (8 + (path << 1));
	dpk_cmd = 0x1000 | (action << 8) | temp;
	/*RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot dpk_cmd = 0x%x\n", dpk_cmd);*/
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd);
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd + 1);
	ODM_delay_ms(5);

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
}

u32 _dpk_pas_get_iq_8198f(
	struct dm_struct *dm,
	boolean is_gain_chk)
{
	s32 i_val = 0, q_val = 0;

	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);

	if (is_gain_chk) {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e03f);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00290000);
	} else {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e038);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00260000);	
	}

	i_val = odm_get_bb_reg(dm, R_0x1bfc, MASKHWORD);
	q_val = odm_get_bb_reg(dm, R_0x1bfc, MASKLWORD);

	if (i_val >> 15 != 0)
		i_val = 0x10000 - i_val;
	if (q_val >> 15 != 0)
		q_val = 0x10000 - q_val;

	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x1);

#if DPK_GAINLOSS_DBG_8198F
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%s] i=0x%x, q=0x%x, i^2+q^2=0x%x\n",
	       is_gain_chk ? "Gain" : "Loss",
	       i_val, q_val, i_val*i_val + q_val*q_val);
#endif
	return i_val*i_val + q_val*q_val;
}


u8 _dpk_pas_iq_check_8198f(
	struct dm_struct *dm,
	u8 limited_pga,
	u32 gain,
	u8 gl_idx)
{
	u8 result = 0;

	if ((gain > 0x100000) && !limited_pga) { /*Gain > 0dB happen*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] Gain > 0dB happen!!\n");
		result = 1;
		return result;
	} else if ((gain < 0x33142) && !limited_pga) { /*Gain < -7dB happen*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] Gain < -7dB happen!!\n");
		result = 2;
		return result;
	} else if (gl_idx < 0x4) { /*GL > criterion*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] GL > criterion happen!!\n");
		result = 3;
		return result;
	} else if (gl_idx == 0xa) { /*GL < criterion*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] GL < criterion happen!!\n");
		result = 4;
		return result;
	} else
		return result;

}

u8 _dpk_gainloss_result_8198f(
	struct dm_struct *dm)
{
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x1);
	odm_write_1byte(dm, R_0x1bd6, 0x26);

	return (u8)odm_get_bb_reg(dm, R_0x1bfc, 0x0000000f);
}

void _dpk_pas_read_8198f(
	struct dm_struct *dm,
	boolean is_gainloss,
	u8 path)
{
	u8 k, j;
	u32 reg_1bfc;

	if (is_gainloss) {
		odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bcc = 0x%x\n",
		       odm_get_bb_reg(dm, R_0x1bcc, MASKDWORD));
#endif
	}

	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, (0x0105e018 | k));
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b90[%d] = 0x%x\n", k,
		       odm_get_bb_reg(dm, R_0x1b90, MASKDWORD));
#endif
		for (j = 0; j < 4; j++) {
			odm_write_1byte(dm, R_0x1bd6, 0x26 + j);
			reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d %s PAS = 0x%x\n",
			       path, is_gainloss ? "GL" : "DPK", reg_1bfc);
		}
	}
}

u8 _dpk_adjust_pga_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 txagc,
	u8 pga,
	u8 gl_idx,
	s32 gain_db)
{
	txagc = txagc - 0xa + gl_idx;

	/*TXAGC for DO DPK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f, txagc);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Gain for DO_DPK will be %d\n",
	       (gain_db - 6020) / 100 - 0xa + gl_idx);

	if (((gain_db - 6020) / 100 - 0xa + gl_idx) < -8) { /*prevent Gain < -8dB*/
		if ((pga == 0x0) || (pga == 0x2))
			pga = 0x1;
		else if (pga == 0x1)
			pga = 0x3;  /*avoid PGA gap*/

		RF_DBG(dm, DBG_RF_DPK, "[DPK] Adjust PGA +1 for DO_DPK\n");

		/*PGA for DO DPK*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x06000, pga);
	}	
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d TXAGC/PGA for DO_DPK= 0x%x / 0x%x\n",
			       path, txagc, pga);
#endif
	ODM_delay_us(2);

	return txagc;
}

u8 _dpk_pas_agc_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 txagc)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 tmp_txagc, tmp_pga, tmp_gl_idx = 0;
	u8 i = 0, goout = 0, limited_pga = 0, agc_cnt = 0;
	u32 loss = 0, gain = 0;
	s32 loss_db = 0, gain_db = 0;

	tmp_txagc = txagc;

	tmp_pga = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x06000);

	do {
		switch (i) {
		case 0: /*one-shot*/

			if (!limited_pga) {
				if (dpk_info->is_dpk_by_channel)
					_dpk_one_shot_8198f(dm, path, GAIN_LOSS_PULSE);
				else
					_dpk_one_shot_8198f(dm, path, GAIN_LOSS);

				tmp_gl_idx = _dpk_gainloss_result_8198f(dm);
			}

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][AGC-%d] TXAGC/PGA/GL_idx = 0x%x / 0x%x / 0x%x\n",
			       agc_cnt, tmp_txagc, tmp_pga, tmp_gl_idx);

			if (DPK_PAS_DBG_8198F)
				_dpk_pas_read_8198f(dm, true, path);
	
			gain = _dpk_pas_get_iq_8198f(dm, GAIN_CHK);
			gain_db = 3 * halrf_psd_log2base(gain);

#if DPK_GAINLOSS_DBG_8198F
			loss = _dpk_pas_get_iq_8198f(dm, LOSS_CHK);
			loss_db = 3 * halrf_psd_log2base(loss);

			RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] G=%d.%02d, L=%d.%02d, GL=%d.%02ddB\n",
			       (gain_db - 6020) / 100, HALRF_ABS(6020, gain_db) % 100,
			       (loss_db - 6020) / 100, HALRF_ABS(6020, loss_db) % 100,
			       (gain_db - loss_db) / 100, (gain_db - loss_db) % 100);
#endif
			i = _dpk_pas_iq_check_8198f(dm, limited_pga, gain, tmp_gl_idx);
			if (i == 0)
				goout = 1;
			agc_cnt++;
			break;

		case 1: /*Gain > criterion*/
			if (tmp_pga == 0x3)
				tmp_pga = 0x1; 	/*avoid PGA gap*/
			else if (tmp_pga == 0x1)
				tmp_pga = 0x0;
			else if ((tmp_pga == 0x0) || (tmp_pga == 0x2)) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA@ lower bound!!\n");
				limited_pga = 1;
			}

			if (limited_pga != 1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x06000, tmp_pga);
				RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] PGA(-1) = 0x%x\n",
				       tmp_pga);
				ODM_delay_us(2);
			}
			i = 0;
			break;

		case 2: /*Gain < criterion*/
			if ((tmp_pga == 0x0) || (tmp_pga == 0x2))
				tmp_pga = 0x1;
			else if (tmp_pga == 0x1)
				tmp_pga = 0x3;  /*avoid PGA gap*/
			else if (tmp_pga == 0x3) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA@ upper bound!!\n");
				limited_pga = 1;
			}

			if (limited_pga != 1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x06000, tmp_pga);
				RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] PGA(+1) = 0x%x\n",
				       tmp_pga);
				ODM_delay_us(2);
			}
			i = 0;
			break;

		case 3: /*GL > criterion*/
			if (tmp_txagc == 0x0) {
				goout = 1;
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] TXAGC@ lower bound!!\n");
				break;
			} else if (tmp_txagc == 0x1)
				tmp_txagc = tmp_txagc - 1;
			else
				tmp_txagc = tmp_txagc - 2;

			odm_set_rf_reg(dm, (enum rf_path)path,
				       RF_0x00, 0x0001f, tmp_txagc);
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] txagc(-) = 0x%x\n",
			       tmp_txagc);
			limited_pga = 0;
			ODM_delay_us(2);
			i = 0;
			break;

		case 4:	/*GL < criterion*/
			if (tmp_txagc == 0x1f) {
				goout = 1;
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] TXAGC@ upper bound!!\n");
				break;
			} else if (0x1f - tmp_txagc == 0x1)
				tmp_txagc = tmp_txagc + 1;
			else
				tmp_txagc = tmp_txagc + 2;

			odm_set_rf_reg(dm, (enum rf_path)path,
				       RF_0x00, 0x0001f, tmp_txagc);
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] txagc(+) = 0x%x\n",
			       tmp_txagc);
			limited_pga = 0;
			ODM_delay_us(2);
			i = 0;
			break;

		default:
			goout = 1;
			break;
	}	
	} while (!goout && (agc_cnt < 6));

	return _dpk_adjust_pga_8198f(dm, path, tmp_txagc, tmp_pga, tmp_gl_idx, gain_db);

}

void _dpk_pas_interpolation_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 k, j;
	u32 reg_1bfc;

	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, (0x0105e018 | k));
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b90[%d] = 0x%x\n", k,
		       odm_get_bb_reg(dm, R_0x1b90, MASKDWORD));
#endif
		for (j = 0; j < 4; j++) {
			odm_write_1byte(dm, R_0x1bd6, 0x26 + j);
			reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
			dpk_info->tmp_pas_i[k*4+j] = (reg_1bfc >> 16) & 0xffff;
			dpk_info->tmp_pas_q[k*4+j] = reg_1bfc & 0xffff;

			if (DPK_PULSE_DBG_8198F)
				RF_DBG(dm, DBG_RF_DPK, "[DPK] Pulse PAS[%02d] = 0x%08x\n",
				       k*4+j, reg_1bfc);
		}
	}
	/*interpolation for even number PAS (0~30)*/
	for (k = 30; k > 0; k -= 2) {
		dpk_info->tmp_pas_i[k] = (dpk_info->tmp_pas_i[k+1] + dpk_info->tmp_pas_i[k-1]) >> 1;
		dpk_info->tmp_pas_q[k] = (dpk_info->tmp_pas_q[k+1] + dpk_info->tmp_pas_q[k-1]) >> 1;

		if (DPK_PULSE_DBG_8198F) {
#if 1
			RF_DBG(dm, DBG_RF_DPK, "[DPK] Insert PAS[%02d] = 0x%08x\n",
			       k, (dpk_info->tmp_pas_i[k] << 16) | dpk_info->tmp_pas_q[k]);
#else
			RF_DBG(dm, DBG_RF_DPK, "[DPK] tmp_pas_i/q[%02d]= 0x%x / 0x%x\n",
			       k, dpk_info->tmp_pas_i[k], dpk_info->tmp_pas_q[k]);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] <<tmp_pas_i/q[%d]= 0x%x / 0x%x>>\n",
			       k+1, dpk_info->tmp_pas_i[k+1], dpk_info->tmp_pas_q[k+1]);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] <<tmp_pas_i/q[%d]= 0x%x / 0x%x>>\n",
			       k-1, dpk_info->tmp_pas_i[k-1], dpk_info->tmp_pas_q[k-1]);
#endif
		}
}

	/*for PAS(31)*/
	dpk_info->tmp_pas_i[0] = dpk_info->tmp_pas_i[2] + (dpk_info->tmp_pas_i[1] - dpk_info->tmp_pas_i[3]);
	dpk_info->tmp_pas_q[0] = dpk_info->tmp_pas_q[2] + (dpk_info->tmp_pas_q[1] - dpk_info->tmp_pas_q[3]);

	if (DPK_PULSE_DBG_8198F) {
		for (k = 0; k < 32 ; k++)
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK PAS(interpolated) = 0x%x\n",
			       path, (dpk_info->tmp_pas_i[k] << 16) | dpk_info->tmp_pas_q[k]);
	}
}

void _dpk_pa_model_write_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 k;
	u16 byte_0, byte_1, byte_2, byte_3;
	u32 val;

	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	for (k = 0; k < 0x20 ; k += 2) {

		byte_0 = (dpk_info->tmp_pas_q[31-k] >> 3) & 0xff;
		byte_1 = (dpk_info->tmp_pas_i[31-k] >> 3) & 0xff;
		byte_2 = (dpk_info->tmp_pas_q[30-k] >> 3) & 0xff;
		byte_3 = (dpk_info->tmp_pas_i[30-k] >> 3) & 0xff;

		val = (byte_3 << 24) | (byte_2 << 16) | (byte_1 << 8) | byte_0;

		odm_set_bb_reg(dm, 0x1b40 | (k * 2), MASKDWORD, val);

		if (DPK_PULSE_DBG_8198F)
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d PA model 0x%x = 0x%x\n",
			       path, 0x1b40 | (k * 2),
			       odm_get_bb_reg(dm, 0x1b40 | (k * 2), MASKDWORD));
	}
}
	
void _dpk_lms_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x020de0b8);
	odm_write_1byte(dm, R_0x1b97, 0xf7);
	odm_set_bb_reg(dm, R_0x1bc8, MASKHWORD, 0x0000);
	odm_set_bb_reg(dm, R_0x1bcc, MASKDWORD, 0x0285083f);

	_dpk_one_shot_8198f(dm, path, DPK_LMS);

	/*tx inverse*/
	odm_set_bb_reg(dm, 0x1b40, MASKDWORD, 0x02ce03e9);
	odm_set_bb_reg(dm, 0x1b44, MASKDWORD, 0x01fd0249);
	odm_set_bb_reg(dm, 0x1b48, MASKDWORD, 0x01a101c9);
	odm_set_bb_reg(dm, 0x1b4c, MASKDWORD, 0x016a0181);
	odm_set_bb_reg(dm, 0x1b50, MASKDWORD, 0x01430155);
	odm_set_bb_reg(dm, 0x1b54, MASKDWORD, 0x01270135);
	odm_set_bb_reg(dm, 0x1b58, MASKDWORD, 0x0112011c);
	odm_set_bb_reg(dm, 0x1b5c, MASKDWORD, 0x01000108);
	odm_set_bb_reg(dm, 0x1b60, MASKDWORD, 0x00f100f8);
	odm_set_bb_reg(dm, 0x1b64, MASKDWORD, 0x00e500eb);
	odm_set_bb_reg(dm, 0x1b68, MASKDWORD, 0x00db00e0);
	odm_set_bb_reg(dm, 0x1b6c, MASKDWORD, 0x00d100d5);
	odm_set_bb_reg(dm, 0x1b70, MASKDWORD, 0x00c900cd);
	odm_set_bb_reg(dm, 0x1b74, MASKDWORD, 0x00c200c5);
	odm_set_bb_reg(dm, 0x1b78, MASKDWORD, 0x00bb00be);
	odm_set_bb_reg(dm, 0x1b7c, MASKDWORD, 0x00b500b8);

	/*DPD off*/
	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));
	odm_set_bb_reg(dm, 0x1b20, BIT(25) | BIT(24), 0x3);

	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e018); /*use LUT SRAM data*/
	}

u8 _dpk_gainloss_8198f(
	struct dm_struct *dm,
	u8 path)
{
	u8 k, tx_agc_search = 0x0, result[5] = {0x0};

	u8 txagc_ori, txagc;

	txagc_ori = _dpk_rf_setting_8198f(dm, path);

	ODM_delay_ms(1);

	odm_write_1byte(dm, R_0x1b92, 0x05);
#if 1
	txagc = _dpk_pas_agc_8198f(dm, path, txagc_ori);
#else
	if (dpk_info->is_dpk_by_channel)
		_dpk_one_shot_8198f(dm, path, GAIN_LOSS_PULSE);
	else
		_dpk_one_shot_8198f(dm, path, GAIN_LOSS);
	_dpk_pas_read_8198f(dm, true, path);
#endif

#if 0
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][GL] S%d RF_0x0/0x86/0x8f/0x56 = 0x%x/ 0x%x/ 0x%x/ 0x%x\n",
	       path, odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x86, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x56, RFREG_MASK));
#endif
	return txagc;
}

u8 _dpk_by_path_8198f(
	struct dm_struct *dm,
	u8 dpk_txagc,
	u8 path,
	u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u32 reg_1bd0;
	u8 result = 1;
	s8 pwsf_idx = 0;

	if (dm->cut_version == 0)
		pwsf_idx = (dpk_txagc - 0x19);
	else
		pwsf_idx = (dpk_txagc - 0x19) - 1;
#if 0
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][DO] S%d RF_0x0=0x%x, 0x86=0x%x, 0x8f=0x%x\n", path,
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x86, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, RFREG_MASK));
#endif
	odm_write_1byte(dm, R_0x1b92, 0x05);

	reg_1bd0 = 0x00000000 | ((pwsf_idx & 0x1f) << 8);

	odm_set_bb_reg(dm, R_0x1bd0, MASKDWORD, reg_1bd0);

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][DO_DPK] pwsf_idx=0x%x,tx_agc=0x%x,0x1bd0=0x%x\n",
		       pwsf_idx & 0x1f, dpk_txagc,
		       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));

	if (dpk_info->is_dpk_by_channel) {
		_dpk_one_shot_8198f(dm, path, DPK_PAS);
		_dpk_pas_interpolation_8198f(dm, path);
		_dpk_pa_model_write_8198f(dm, path);
		_dpk_lms_8198f(dm, path);
		odm_write_1byte(dm, R_0x1b23, 0x07); /*dpd off*/
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e018); /*use LUT SRAM data*/
		odm_set_bb_reg(dm, R_0x1bcc, MASKHWORD, 0x1982); /*bypass pa!=11*/
	} else
	_dpk_one_shot_8198f(dm, path, DO_DPK);
#if 0
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x002a0000);
	result = (u8)odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
#endif
	result = (u8)odm_get_bb_reg(dm, R_0x1b08, BIT(26));
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] fail bit = %x\n", result);

	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, 0xf0000, 0x3);

	if (DPK_PAS_DBG_8198F)
		_dpk_pas_read_8198f(dm, false, path);

	return result;
}

boolean _dpk_lms_iq_check_8198f(
	struct dm_struct *dm,
	u8 addr,
	u32 reg_1bfc)
{
	u32 i_val = 0, q_val = 0;

	if (DPK_SRAM_IQ_DBG_8198F && (addr < 16))
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] 0x1bfc[%2d] = 0x%x\n", addr, reg_1bfc);

	i_val = (reg_1bfc & 0x003FF800) >> 11;
		q_val = reg_1bfc & 0x000007FF;

		if (((q_val & 0x400) >> 10) == 1)
			q_val = 0x800 - q_val;

	if ((addr == 0) && ((i_val*i_val + q_val*q_val) < 0x23fd6)) {
		/* LMS (I^2 + Q^2) < -2.5dB happen 0x2851e*/
			RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT < -2.5dB happen, I=0x%x, Q=0x%x\n",
			       i_val, q_val);
			return 1;
	} else if ((i_val*i_val + q_val*q_val) > 0x50924) {
		/* LMS (I^2 + Q^2) > 1dB happen*/
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT > 1dB happen, I=0x%x, Q=0x%x\n",
		       i_val, q_val);
		return 1;
	} else
		return 0;
	}

void _dpk_on_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	_dpk_one_shot_8198f(dm, path, DPK_ON);

	/*I_Gain @ 1b98[31:16], Q_Gain @ 1b98[15:0]*/
	/*odm_set_bb_reg(dm, R_0x1b98, MASKDWORD, 0x4c104c10);*/
	odm_set_bb_reg(dm, R_0x1b98, MASKDWORD, 0x50925092);

	/*[12] TX CCK mode DPD enable*/
	odm_set_bb_reg(dm, R_0x1bcc, BIT(13) | BIT(12), 0x0);

	/*add for no DPK, read LUT from flash directly*/
	odm_set_bb_reg(dm, R_0x1e24, BIT(17), 0x1);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPD enable!!!\n\n", path);
}

u8 dpk_channel_transfer_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 channel, bandwidth, i;

	channel = *dm->channel;
	bandwidth = *dm->band_width;

	if (channel <= 4)
		i = 0;
	else if (channel >= 5 && channel <= 8)
		i = 1;
	else if (channel >= 9)
		i = 2;

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] channel = %d, bandwidth = %d, transfer idx = %d\n",
	       channel, bandwidth, i);

	return i;
}

void dpk_sram_read_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, addr, group_number;

	if (dpk_info->is_dpk_by_channel)
		group_number = 1;
	else
		group_number = DPK_GROUP_NUM_8198F;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Start =========\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		for (group = 0; group < group_number; group++) {
			for (addr = 0; addr < 16; addr++)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read S%d[%d] even[%2d]= 0x%x\n",
				       path, group, addr,
				       dpk_info->lut_2g_even[path][group][addr]);

			for (addr = 0; addr < 16; addr++)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read S%d[%d]  odd[%2d]= 0x%x\n",
				       path, group, addr,
				       dpk_info->lut_2g_odd[path][group][addr]);
}
		}
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Finish =========\n");
}

u8 _dpk_lut_sram_read_8198f(
	void *dm_void,
	u8 group,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, i, j;
	u32 reg_1bdc = 0, reg_1bfc = 0;

	/*even*/
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00220001);

	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);

			addr = (i - 1) / 2;
		if (_dpk_lms_iq_check_8198f(dm, addr, reg_1bfc))
			return 0;
		else
			dpk_info->lut_2g_even[path][group][addr] = reg_1bfc;
		}

	/*odd*/
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00230001);

	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);

			addr = (i - 1) / 2;
		if (_dpk_lms_iq_check_8198f(dm, addr, reg_1bfc))
			return 0;
		else
			dpk_info->lut_2g_odd[path][group][addr] = reg_1bfc;
		}

	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);

	return 1;
}

void _dpk_lut_sram_write_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, group, path;
	u32 reg_1bdc_even, reg_1bdc_odd, temp1, temp2, temp3;

	group = dpk_channel_transfer_8198f(dm);

	reg_1bdc_even = 0xc0000000;
	reg_1bdc_odd = 0x80000080;

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
		/*write_even*/
		for (addr = 0; addr < 16; addr++) {
			temp1 = dpk_info->lut_2g_even[path][group][addr];
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_even | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));

		if (DPK_SRAM_write_DBG_8198F)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d] even[%2d]= 0x%x\n",
			       path, group, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));

		}

		/*write_odd*/
		for (addr = 0; addr < 16; addr++) {
			temp1 = dpk_info->lut_2g_odd[path][group][addr];
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_odd | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));

			if (DPK_SRAM_write_DBG_8198F)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d]  odd[%2d]= 0x%x\n",
			       path, group, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));
		}

		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);

		odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00,
			       dpk_info->pwsf_2g[path][group]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S%d[%d] pwsf = 0x%x\n",
		       path, group, dpk_info->pwsf_2g[path][group]);
#endif
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S%d[%d] 0x1bd0 = 0x%x\n",
		       path, group, odm_get_bb_reg(dm, R_0x1bd0, 0x00001f00));
	}
}

u8 _dpk_check_fail_8198f(
	struct dm_struct *dm,
	boolean is_fail,
	u8 path,
	u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 result = 0;

	if (!is_fail) {
		if (_dpk_lut_sram_read_8198f(dm, group, path)) {
			dpk_info->pwsf_2g[path][group] = (u8)odm_get_bb_reg(dm,
				R_0x1bd0, 0x00001F00);
			dpk_info->dpk_result[path][group] = 1;
			result = 1;
		} else {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_result[path][group] = 0;
			result = 0;
		}
	} else {
		_dpk_lut_sram_read_8198f(dm, group, path);
		dpk_info->pwsf_2g[path][group] = 0;
		dpk_info->dpk_result[path][group] = 0;
		result = 0;
	}

	return result;
}

void _dpk_result_reset_8198f(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group;

	dpk_info->dpk_path_ok = 0;

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		for (group = 0; group < DPK_GROUP_NUM_8198F; group++) {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_result[path][group] = 0;
#if 0
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][reset] S%d pwsf[%d]=0x%x, dpk_result[%d]=%d\n",
		       path, group, dpk_info->pwsf_2g[path][group],
		       group, dpk_info->dpk_result[path][group],
#endif
		}
	}
}

void _dpk_calibrate_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 dpk_fail = 1, dpk_txagc = 0;
	u8 group, retry_cnt, group_number;

	if (dpk_info->is_dpk_by_channel) {
		group_number = 1;
		_dpk_information_8198f(dm);
	} else
		group_number = DPK_GROUP_NUM_8198F;

	_dpk_bb_path_setting_8198f(dm, path);
	_dpk_con_tx_8198f(dm, true);

	for (group = 0; group < group_number; group++) {
		if (!dpk_info->is_dpk_by_channel)
		_dpk_set_group_8198f(dm, group);

		for (retry_cnt = 0; retry_cnt < 1; retry_cnt++) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK] Group%d retry =%d\n",
			       group, retry_cnt);

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] ========= S%d[%d] DPK Start =========\n",
			       path, group);

			dpk_txagc = _dpk_gainloss_8198f(dm, path);

			ODM_delay_ms(1);

			dpk_fail = _dpk_by_path_8198f(dm, dpk_txagc,
						      path, group);

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] ========= S%d[%d] DPK Finish ========\n",
			       path, group);

			if (_dpk_check_fail_8198f(dm, dpk_fail, path, group))
				break;
		}
	}

	_dpk_con_tx_8198f(dm, false);

	if (dpk_info->is_dpk_by_channel && dpk_info->dpk_result[path][0])
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);

	else if (dpk_info->dpk_result[path][0] &&
		 dpk_info->dpk_result[path][1] &&
		 dpk_info->dpk_result[path][2])
			dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);
}

void _dpk_path_select_8198f(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

#if DPK_DO_PATH_A
	
	_dpk_calibrate_8198f(dm, RF_PATH_A);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_A)) >> RF_PATH_A)
	_dpk_on_8198f(dm, RF_PATH_A);
#endif

#if DPK_DO_PATH_B
	_dpk_calibrate_8198f(dm, RF_PATH_B);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_B)) >> RF_PATH_B)
	_dpk_on_8198f(dm, RF_PATH_B);
#endif

#if DPK_DO_PATH_C
	_dpk_calibrate_8198f(dm, RF_PATH_C);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_C)) >> RF_PATH_C)
	_dpk_on_8198f(dm, RF_PATH_C);
#endif

#if DPK_DO_PATH_D
	_dpk_calibrate_8198f(dm, RF_PATH_D);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_D)) >> RF_PATH_D)
	_dpk_on_8198f(dm, RF_PATH_D);
#endif
}

void _dpk_result_summary_8198f(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, group_number;

	if (dpk_info->is_dpk_by_channel)
		group_number = 1;
	else
		group_number = DPK_GROUP_NUM_8198F;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

	RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK by %s\n",
	       dpk_info->is_dpk_by_channel ? "Channel" : "Group");

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		for (group = 0; group < group_number; group++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] S%d[%d] pwsf = 0x%x, dpk_result = %d\n",
			       path, group, dpk_info->pwsf_2g[path][group],
			       dpk_info->dpk_result[path][group]);
		}

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] S%d DPK is %s\n", path,
		       ((dpk_info->dpk_path_ok & BIT(path)) >> path) ?
		       "Success" : "Fail");
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] dpk_path_ok = 0x%x\n",
	       dpk_info->dpk_path_ok);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

	if (DPK_SRAM_read_DBG_8198F)
	dpk_sram_read_8198f(dm);
	
}

void dpk_reload_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path;

	if (!dpk_info->is_dpk_by_channel) {
	_dpk_lut_sram_write_8198f(dm);

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));

		if ((dpk_info->dpk_path_ok & BIT(path)) >> path)
			_dpk_on_8198f(dm, path);
		else
			odm_set_bb_reg(dm, R_0x1b20, 0x07000000, 0x7);
	}
	}

	dpk_enable_disable_8198f(dm);
}

void do_dpk_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	u32 mac_reg_backup[DPK_MAC_REG_NUM_8198F];
	u32 bb_reg_backup[DPK_BB_REG_NUM_8198F];
	u32 rf_reg_backup[DPK_RF_REG_NUM_8198F][DPK_RF_PATH_NUM_8198F];

	u32 mac_reg[DPK_MAC_REG_NUM_8198F] = {R_0x520, R_0x550};
	u32 bb_reg[DPK_BB_REG_NUM_8198F] = {
		R_0x820, R_0x824, R_0x1c38, R_0x1c3c, R_0x1c68, R_0x1d60};
	u32 rf_reg[DPK_RF_REG_NUM_8198F] = {RF_0x0, RF_0x18, RF_0x86, RF_0x8f};

	u8 path, retry_cnt = 0;

	if (dm->ext_pa) {
		panic_printk("[DPK] Skip DPK due to ext_PA exist!!\n");
		return;
	} else {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] DPK Start (Ver: %s), Cv: %d, Package: %d\n",
		       DPK_VER_8198F, dm->cut_version, dm->package_type);
	}

	_backup_mac_bb_registers_8198f(dm, mac_reg, mac_reg_backup,
				       DPK_MAC_REG_NUM_8198F);
	_backup_mac_bb_registers_8198f(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8198F);
	_backup_rf_registers_8198f(dm, rf_reg, rf_reg_backup);

	_dpk_mac_bb_setting_8198f(dm);
	_dpk_afe_setting_8198f(dm, true);
	_dpk_manual_txagc_8198f(dm, true);
	_dpk_pre_setting_8198f(dm);

	_dpk_result_reset_8198f(dm);
	_dpk_path_select_8198f(dm);
	_dpk_result_summary_8198f(dm);

	_dpk_manual_txagc_8198f(dm, false);
	_dpk_afe_setting_8198f(dm, false);

	_reload_rf_registers_8198f(dm, rf_reg, rf_reg_backup);
	_reload_mac_bb_registers_8198f(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8198F);
	_reload_mac_bb_registers_8198f(dm, mac_reg, mac_reg_backup,
				       DPK_MAC_REG_NUM_8198F);
	dpk_reload_8198f(dm);

}

void dpk_enable_disable_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path;

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
			odm_set_bb_reg(dm, R_0x1b00, MASKDWORD,
				       0x8 | (path << 1));

			if (dpk_info->is_dpk_enable) {
				odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x0);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] S%d DPK enable !!!\n", path);
			} else {
				odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x1);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] S%d DPK bypass !!!\n", path);
			}
		}
	}
}

void dpk_track_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct rtl8192cd_priv *priv = dm->priv;

	s8 pwsf_a, pwsf_b, pwsf_c, pwsf_d;
	u8 offset, delta_dpk, is_increase, thermal_value = 0, i = 0, k = 0;
	u8 thermal_dpk_avg_count = 0;
	u32 thermal_dpk_avg = 0;
	u8 path, pwsf[4] = {0};
	s8 idx_offset[4] = {0};

#if (DM_ODM_SUPPORT_TYPE & (ODM_AP))
#ifdef MP_TEST
	if ((OPMODE & WIFI_MP_STATE) || priv->pshare->rf_ft_var.mp_specific) {
		if (priv->pshare->mp_tx_dpk_tracking == false)
			return;
	}
#endif
#endif
	RF_DBG(dm, DBG_RF_DPK, "[DPK track] ======================================\n");

	idx_offset[RF_PATH_A] = (u8)odm_get_bb_reg(dm, R_0x18a0, 0x0000007F);
	idx_offset[RF_PATH_B] = (u8)odm_get_bb_reg(dm, R_0x41a0, 0x0000007F);
	idx_offset[RF_PATH_C] = (u8)odm_get_bb_reg(dm, R_0x52a0, 0x0000007F);
	idx_offset[RF_PATH_D] = (u8)odm_get_bb_reg(dm, R_0x53a0, 0x0000007F);

	if (!dpk_info->is_dpk_by_channel)
		k = dpk_channel_transfer_8198f(dm);

	for (path = 0; path < DPK_RF_PATH_NUM_8198F; path++) {
		if ((idx_offset[path] >> 6) == 1) {/*minus*/

			idx_offset[path] = (idx_offset[path] - 0x80);

			if (idx_offset[path] % 4 == 0)
				idx_offset[path] = idx_offset[path] / 4 + 1;
			else
				idx_offset[path] = idx_offset[path] / 4;

		} else if (idx_offset[path] > 0) {/*plus*/

			if (idx_offset[path] % 4 == 0)
				idx_offset[path] = idx_offset[path] / 4 - 1;
			else
				idx_offset[path] = idx_offset[path] / 4;
		}

		pwsf[path] = dpk_info->pwsf_2g[path][k];
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK track] S%d pwsf[%d] (ori) is 0x%x, txidx_offset= %d\n",
	 	       path, k, pwsf[path], idx_offset[path]);		

		pwsf[path] = (pwsf[path] + idx_offset[path]) & 0x1f;

		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
		odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf[path]);
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK track] S%d pwsf[%d] (after) is 0x%x, 0x1bd0=0x%x\n",
	 	       path, k, pwsf[path],
	 	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));
	}

#if 0
	if (!dpk_info->thermal_dpk)
		dpk_info->thermal_dpk = rf->eeprom_thermal;

	/* calculate average thermal meter */

	 /*thermal meter trigger*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_T_METER_8198F, BIT(17) | BIT(16), 0x3);
	ODM_delay_ms(1);

	/*get thermal meter*/
	thermal_value =
		(u8)odm_get_rf_reg(dm, RF_PATH_A, RF_T_METER_8198F, 0xfc00);

	dpk_info->thermal_dpk_avg[dpk_info->thermal_dpk_avg_index] =
		thermal_value;
	dpk_info->thermal_dpk_avg_index++;

	/*Average times */
	if (dpk_info->thermal_dpk_avg_index == THERMAL_DPK_AVG_NUM)
		dpk_info->thermal_dpk_avg_index = 0;

	for (i = 0; i < THERMAL_DPK_AVG_NUM; i++) {
		if (dpk_info->thermal_dpk_avg[i]) {
			thermal_dpk_avg += dpk_info->thermal_dpk_avg[i];
			thermal_dpk_avg_count++;
		}
	}

	/*Calculate Average ThermalValue after average enough times*/
	if (thermal_dpk_avg_count) {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK_track] ThermalValue_DPK_AVG (count) = %d (%d))\n",
		       thermal_dpk_avg, thermal_dpk_avg_count);

		thermal_value = (u8)(thermal_dpk_avg / thermal_dpk_avg_count);

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK_track] AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value, rf->eeprom_thermal);
	}

	delta_dpk = RTL_ABS(thermal_value, rf->eeprom_thermal);
	is_increase = ((thermal_value < rf->eeprom_thermal) ? 0 : 1);

	offset = delta_dpk / DPK_THRESHOLD_8198F;

	k = dpk_channel_transfer_8198f(dm);

	pwsf_a = dpk_info->pwsf_2g[0][k];
	pwsf_b = dpk_info->pwsf_2g[1][k];
	pwsf_c = dpk_info->pwsf_2g[2][k];
	pwsf_d = dpk_info->pwsf_2g[3][k];

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] delta_DPK=%d, offset=%d, track direction is %s\n",
	       delta_dpk, offset, (is_increase ? "Plus" : "Minus"));

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_a before tracking is 0x%x\n", pwsf_a);

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_b before tracking is 0x%x\n", pwsf_b);

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_c before tracking is 0x%x\n", pwsf_c);

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_d before tracking is 0x%x\n", pwsf_d);

	if ((pwsf_a >> 4) != 0)
		pwsf_a = (pwsf_a | 0xe0);

	if ((pwsf_b >> 4) != 0)
		pwsf_b = (pwsf_b | 0xe0);

	if ((pwsf_c >> 4) != 0)
		pwsf_c = (pwsf_c | 0xe0);

	if ((pwsf_d >> 4) != 0)
		pwsf_d = (pwsf_d | 0xe0);

	if (is_increase) {
		pwsf_a = pwsf_a + offset;
		pwsf_b = pwsf_b + offset;
		pwsf_c = pwsf_c + offset;
		pwsf_d = pwsf_d + offset;
	} else {
		pwsf_a = pwsf_a - offset;
		pwsf_b = pwsf_b - offset;
		pwsf_c = pwsf_c - offset;
		pwsf_d = pwsf_d - offset;
	}

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x00000008);
	odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf_a);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_a after tracking is %d (0x%x),0x1bd0=0x%x\n",
	       pwsf_a, (pwsf_a & 0x1f),
	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x0000000a);
	odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf_b);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_b after tracking is %d (0x%x), 0x1bd0=0x%x\n",
	       pwsf_b, (pwsf_b & 0x1f),
	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x0000000c);
	odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf_c);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_c after tracking is %d (0x%x), 0x1bd0=0x%x\n",
	       pwsf_c, (pwsf_c & 0x1f),
	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x0000000e);
	odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf_d);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_d after tracking is %d (0x%x), 0x1bd0=0x%x\n",
	       pwsf_d, (pwsf_d & 0x1f),
	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));
#endif
}
#endif
