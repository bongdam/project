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

#if (RTL8197G_SUPPORT == 1)

/*---------------------------Define Local Constant---------------------------*/

/*8197G DPK ver:0x6 20190612*/

void _backup_mac_bb_registers_8197g(
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

void _backup_rf_registers_8197g(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 rf_reg_backup[][DPK_RF_PATH_NUM_8197G])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8197G; i++) {
		rf_reg_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A,
			rf_reg[i], RFREG_MASK);
		rf_reg_backup[i][RF_PATH_B] = odm_get_rf_reg(dm, RF_PATH_B,
			rf_reg[i], RFREG_MASK);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_B 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_B]);
#endif
	}
}

void _reload_mac_bb_registers_8197g(
	struct dm_struct *dm,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)

{
	u32 i;

	/*toggle IGI*/
	odm_write_4byte(dm, 0x1d70, 0x50505050);

	for (i = 0; i < reg_num; i++) {
		odm_write_4byte(dm, reg[i], reg_backup[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload MAC/BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
	odm_set_bb_reg(dm, R_0x1e24, BIT(31), 0x1);     /*enable r_path_en*/
}

void _reload_rf_registers_8197g(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 rf_reg_backup[][DPK_RF_PATH_NUM_8197G])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8197G; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_A]);
		odm_set_rf_reg(dm, RF_PATH_B, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_B]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_B 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_B]);
#endif
	}
}

void _dpk_information_8197g(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u32  reg_rf18;

	if (odm_get_bb_reg(dm, R_0x1e7c, BIT(30)))
		dpk_info->is_tssi_mode = true;
	else
		dpk_info->is_tssi_mode = false;

	reg_rf18 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK);

	dpk_info->dpk_ch = (u8)reg_rf18 & 0xff;
	dpk_info->dpk_bw = (u8)((reg_rf18 & 0xc00) >> 10); /*3/2:20/40*/

	RF_DBG(dm, DBG_RF_DPK, "[DPK] TSSI / CH / BW = %s / %d / %s\n",
	       dpk_info->is_tssi_mode ? "ON" : "OFF", dpk_info->dpk_ch,
	       dpk_info->dpk_bw == 3 ? "20M" : "40M");
}

void _dpk_clear_even_odd_8197g(
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

void _dpk_tx_pause_8197g(
	struct dm_struct *dm)
{
	u8 reg_rf0_a, reg_rf0_b;
	u16 count = 0;

	odm_write_1byte(dm, R_0x522, 0xff);
	odm_set_bb_reg(dm, R_0x1e70, 0x0000000f, 0x2); /*hw tx stop*/

	reg_rf0_a = (u8)odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0xF0000);
	reg_rf0_b = (u8)odm_get_rf_reg(dm, RF_PATH_B, RF_0x00, 0xF0000);

	while (((reg_rf0_a == 2) || (reg_rf0_b == 2)) && count < 2500) {
		reg_rf0_a = (u8)odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0xF0000);
		reg_rf0_b = (u8)odm_get_rf_reg(dm, RF_PATH_B, RF_0x00, 0xF0000);
		ODM_delay_us(2);
		count++;
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Tx pause!!\n");
}

void _dpk_mac_bb_setting_8197g(
	struct dm_struct *dm)
{	
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	_dpk_tx_pause_8197g(dm);

	/*disable TSSI*/
	odm_set_bb_reg(dm, R_0x1e7c, BIT(30), 0x0);
	odm_set_bb_reg(dm, R_0x18a4, BIT(28), 0x0);
	odm_set_bb_reg(dm, R_0x41a4, BIT(28), 0x0);

	odm_set_bb_reg(dm, R_0x1e24, BIT(31), 0x0);     /*disable r_path_en*/
	odm_set_bb_reg(dm, R_0x1e28, 0x0000000f, 0x3);  /*tx_iqk_path*/

	/*Rx path must set before r_soft3wire_data*/
	odm_set_bb_reg(dm, R_0x824, 0x000f0000, 0x3);
	odm_set_bb_reg(dm, R_0x1808, MASKDWORD, 0x00050000); /*soft3wire_data s0*/
	odm_set_bb_reg(dm, R_0x4108, MASKDWORD, 0x00050000); /*soft3wire_data s1*/

	/*Prevent CCK CCA at sine PSD*/
	odm_set_bb_reg(dm, R_0x1a00, BIT(1) | BIT(0), 0x2);

	odm_set_bb_reg(dm, R_0x1e24, BIT(17), 0x1);  /*r_gothrough_iqkdpk*/

	/*BB CCA off*/
	odm_set_bb_reg(dm, R_0x1d58, BIT(3), 0x1);
	odm_set_bb_reg(dm, R_0x1d58, 0x00000ff0, 0xff);

	/*wire r_rftxen_gck_force_on*/
	odm_set_bb_reg(dm, R_0x1864, BIT(31), 0x1); /*s0*/
	odm_set_bb_reg(dm, R_0x4164, BIT(31), 0x1); /*s1*/

	/*wire r_dis_sharerx_txgat*/
	odm_set_bb_reg(dm, R_0x180c, BIT(27), 0x1); /*s0*/
	odm_set_bb_reg(dm, R_0x410c, BIT(27), 0x1); /*s1*/

	/*3-wire off*/
	odm_set_bb_reg(dm, R_0x180c, BIT(1) | BIT(0), 0x0);
	odm_set_bb_reg(dm, R_0x410c, BIT(1) | BIT(0), 0x0);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] MAC/BB setting for DPK mode\n");
}

void _dpk_manual_txagc_8197g(
	struct dm_struct *dm,
	boolean is_manual)
{
	odm_set_bb_reg(dm, R_0x18a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x41a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x52a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x53a4, BIT(7), is_manual);
}

void _dpk_afe_setting_8197g(
	struct dm_struct *dm,
	boolean is_do_dpk)
{
	if (is_do_dpk) {
		/*ADDA FIFO reset on*/
		odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xffffffff);

		/*s0*/
		odm_set_bb_reg(dm, R_0x1810, MASKDWORD, 0xB3001402);
		odm_set_bb_reg(dm, R_0x1814, MASKDWORD, 0x06000141);
		odm_set_bb_reg(dm, R_0x1818, MASKDWORD, 0x00000280);
		odm_set_bb_reg(dm, R_0x181c, MASKDWORD, 0x00000000);

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

		/*s1*/
		odm_set_bb_reg(dm, R_0x4110, MASKDWORD, 0xB3001402);
		odm_set_bb_reg(dm, R_0x4114, MASKDWORD, 0x06000141);
		odm_set_bb_reg(dm, R_0x4118, MASKDWORD, 0x00000280);
		odm_set_bb_reg(dm, R_0x411c, MASKDWORD, 0x00000000);
		
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

		RF_DBG(dm, DBG_RF_DPK, "[DPK] AFE for DPK mode\n");
	} else {
		odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xF7D5005E);

		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x703f0044);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x706f0044);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70fb8041);
                                                        
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x703f0044);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x706f0044);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70fb8041);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] AFE for Normal mode\n");
	}
}

void _dpk_pre_setting_8197g(
	struct dm_struct *dm)
{
	u8 path;

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));

		odm_set_bb_reg(dm, R_0x1be8, 0x7F000000, 0x0);

		if (dm->cut_version == 0) {		
			/*write sram0 pwsf*/
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40caff81);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x4080a183);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40516585);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40334087);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40202889);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x4014198b);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x400d108d);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40080a8f);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40050691);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40030493);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40020395);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40010297);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x40010199);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x4001019b);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x4001019d);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x4001019f);
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
		}
	}

	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x00000008);
	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e018);

}

u8 _dpk_rf_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK, 0x5001b);

	/*coupling ATT*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x85, 0x00F00, 0xA);
	/*TIA_R1*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x86, 0x0F000, 0x5);
	/*Test switch*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x85, 0x03000, 0x1);  
	/*Pow_TXLPBK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x80, BIT(0), 0x1);  
	/*TIA gain*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(16), 0x1);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x83,0x00030, 0x2);
	/*PGA gain*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f,0x0e000, 0x3);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d init TXAGC/TIA/PGA = 0x%x / 0x%x / 0x%x\n",
	       path, odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x83, 0x00030),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x0e000));

	return odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f);
}

u8 _dpk_thermal_read_8197g(
	struct dm_struct *dm,
	u8 path)
{
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x42, BIT(17), 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x42, BIT(17), 0x1);
	ODM_delay_us(15);

	return (u8)odm_get_rf_reg(dm, (enum rf_path)path, RF_0xf6, 0x7E000);
}

void _dpk_one_shot_8197g(
	struct dm_struct *dm,
	u8 action)
{
	u8 k_done;
	u16 count = 0;

	if (action == GAIN_LOSS) { /*PA scan*/

		odm_write_1byte(dm, R_0x1b84, 0xA0);
		odm_write_1byte(dm, R_0x1b84, 0x20);

		ODM_delay_us(20); /*wait sync done from 1-> 0*/

		odm_write_1byte(dm, R_0x1bd6, 0x12);

	} else if (action == DO_DPK) { /*LMS*/

		odm_write_1byte(dm, R_0x1b34, 0x02);
		odm_write_1byte(dm, R_0x1b34, 0x00);

		ODM_delay_us(20); /*wait sync done from 1-> 0*/

		odm_write_1byte(dm, R_0x1bd6, 0x0a);
	}

	k_done = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(0));
	while (k_done != 0x1 && count < 1000) {
		ODM_delay_us(20);
		k_done = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(0));
		count++;
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot for %s (count=%d)\n",
	       action == 1 ? "PAS" : "LMS", count);

	if (count == 1000)
		RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot over 20ms!!!!\n");
}

u8 _dpk_dc_corr_check_8197g(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u16 dc_i, dc_q;
	u8 corr_val, corr_idx;
	
	corr_idx = (u8)odm_get_bb_reg(dm, 0x1bfc, 0x000000ff);
	corr_val = (u8)odm_get_bb_reg(dm, 0x1bfc, 0x0000ff00);

	dpk_info->corr_idx[path] = corr_idx;
	dpk_info->corr_val[path] = corr_val;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d Corr_idx / Corr_val = %d / %d\n",
	       path, corr_idx, corr_val);
	
	odm_write_1byte(dm, 0x1bd6, 0x0d);
	dc_i = (u16)odm_get_bb_reg(dm, 0x1bfc, 0x03ff0000);
	dc_q = (u16)odm_get_bb_reg(dm, 0x1bfc, 0x000003ff);

	if (dc_i >> 9 == 1)
		dc_i = 0x400 - dc_i;
	if (dc_q >> 9 == 1)
		dc_q = 0x400 - dc_q;

	dpk_info->dc_i[path] = dc_i;
	dpk_info->dc_q[path] = dc_q;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DC I/Q, = %d / %d\n", path, dc_i, dc_q);

	if ((dc_i > 200) || (dc_q > 200) || (corr_idx < 40) || (corr_idx > 65))
		return 1;
	else
		return 0;
}

u8 _dpk_timing_sync_8197g(
	struct dm_struct *dm,
	u8 path)
{
	u8 result, sync_done;
	u16 count = 0;

	odm_write_1byte(dm, R_0x1b97, 0xf7);
	odm_write_1byte(dm, R_0x1b23, 0x00); /*bypass DPD*/
	odm_set_bb_reg(dm, R_0x1bcc, BIT(16), 0x0); /*DPK FS 160M*/

	odm_set_bb_reg(dm, R_0x1b88, MASKDWORD, 0x01b40000);
	odm_set_bb_reg(dm, R_0x1b88, MASKDWORD, 0x00b40000);

	ODM_delay_us(50); /*wait sync done from 1-> 0*/

	odm_write_1byte(dm, R_0x1bd6, 0x0c);

	sync_done = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(31));
	while (sync_done != 0x1 && count < 1000) {
		ODM_delay_us(20);
		sync_done = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(31));
		count++;
	}

	if (count == 1000)
		RF_DBG(dm, DBG_RF_DPK, "[DPK] timing sync one-shot over 20ms!!!!\n");

	result = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(30));

	_dpk_dc_corr_check_8197g(dm, path);
	
	return result;
}

s16 _dpk_get_gainloss_8197g(
	struct dm_struct *dm,
	boolean is_gain_chk)
{
	s16 result;

	if (is_gain_chk) { /*result = sqrt(I^2 + Q^2), s(14,9)*/
		odm_write_1byte(dm, R_0x1bd6, 0x02);
		result = (s16)odm_get_bb_reg(dm, R_0x1bfc, 0x00003FFF); /*gain(0)*/
	} else {
		odm_write_1byte(dm, R_0x1bd6, 0x01);
		result = (s16)odm_get_bb_reg(dm, R_0x1bfc, 0x3FFF0000); /*gain(31)*/
	}
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] %s = 0x%x\n",
	       is_gain_chk ? "Gain" : "Loss", result);
#endif

	if (result >> 13 != 0)
		result = 0xc000 | result;

	result = (6 * result * 100) >> 9;

	return result; 
}

u8 _dpk_pas_check_8197g(
	struct dm_struct *dm)
{
	u8 result = 0;
	s16 loss_db, gain_db;
	
	loss_db = _dpk_get_gainloss_8197g(dm, LOSS_CHK);
	gain_db = _dpk_get_gainloss_8197g(dm, GAIN_CHK);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][CHK] G=%d.%02d, L=%d.%02d, GL=%d.%02ddB\n",
	       gain_db / 100, HALRF_ABS(0, gain_db) % 100,
	       loss_db / 100, HALRF_ABS(0, gain_db) % 100,
	       (gain_db - loss_db) / 100, (gain_db - loss_db) % 100);

	if ((loss_db - gain_db) > 400) {/*check if GL > 4dB*/
		result = 1;
		RF_DBG(dm, DBG_RF_DPK, "[DPK][CHK] GL > 4dB happen!!\n");
	}

	odm_write_1byte(dm, R_0x1bd6, 0x02);

	if (odm_get_bb_reg(dm, R_0x1bfc, BIT(24)) && loss_db < 1400) {
		result = 1;
		RF_DBG(dm, DBG_RF_DPK, "[DPK][CHK] PAS < -14dB happen!!\n");
	}

	return result;
}

u8 _dpk_gainloss_result_8197g(
	struct dm_struct *dm,
	u8 path)
{
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x1);
	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e038);
	odm_write_1byte(dm, R_0x1bd6, 0x06);

	return (u8)odm_get_bb_reg(dm, R_0x1bfc, 0x0000000f);
}

void _dpk_pas_read_8197g(
	struct dm_struct *dm,
	u8 path)
{
	u8 k, j;
	u32 reg_1bfc;

	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);

	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e018 + k);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b90[%d] = 0x%x\n", k,
		       odm_get_bb_reg(dm, R_0x1b90, MASKDWORD));
#endif
		for (j = 0; j < 4; j++) {
			odm_write_1byte(dm, R_0x1bd6, 0x06 + j);
			reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d PAS read = 0x%x\n",
			       path, reg_1bfc);
		}
	}
}

u8 _dpk_auto_pga_8197g(
	struct dm_struct *dm,
	u8 path)
{
	u8 tmp_pga;

	/*ensure PGA = 0x3 before calling this function, or the result may incorrect*/

	odm_set_bb_reg(dm, R_0x1bcc, BIT(20), 0x1); /*PAScan data big to small*/
	odm_write_1byte(dm, R_0x1bef, 0xa2); /*PGA2 auto K (-6dB<gain<=-4dB)*/
	odm_write_1byte(dm, R_0x1b84, 0x00);

	_dpk_one_shot_8197g(dm, GAIN_LOSS);

	odm_write_1byte(dm, R_0x1bd6, 0x02);

	tmp_pga = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(18) | BIT(17) | BIT(16));
	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x0e000, tmp_pga);

	odm_write_1byte(dm, R_0x1bef, 0x22); /*disable PGA2 auto K*/

	_dpk_one_shot_8197g(dm, GAIN_LOSS);

	return tmp_pga;
}

u8 _dpk_adjust_pga_8197g(
	struct dm_struct *dm,
	u8 path,
	u8 txagc,
	u8 pga,
	u8 gl_idx)
{
	u8 offset;

	txagc = txagc - 0xa + gl_idx;

	offset = (0xa - gl_idx) >> 1;

	if (offset > 0 && pga != 0x7) {
		if (pga == 0x3 || (pga + offset > 0x3)) /*due to PGA gap*/
			pga = pga + offset + 1;
		else
			pga = pga + offset;

		RF_DBG(dm, DBG_RF_DPK, "[DPK] Adjust PGA +%d for DPK\n", offset);
	}
		
	if (pga > 0x7)
		pga = 0x7;

	/*TXAGC for DO DPK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f, txagc);

	/*PGA for DO DPK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x0e000, pga);
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][ADJ] S%d TXAGC/PGA for DPK= 0x%x / 0x%x\n",
			       path, txagc, pga);
#endif
	ODM_delay_us(5);

	return txagc;
}

u8 _dpk_pas_agc_8197g(
	struct dm_struct *dm,
	u8 path,
	u8 txagc)
{
	u8 i = 0, goout = 0, limited_pga = 0, agc_cnt = 0;
	u8 tmp_txagc, tmp_pga, tmp_gl_idx = 0;
	s16 tmp_gain, tmp_loss;

	tmp_pga = _dpk_auto_pga_8197g(dm, path);

	tmp_txagc = txagc;

	tmp_gl_idx = _dpk_gainloss_result_8197g(dm, path);

	do {
		switch (i) {
		case 0:
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][AGC-%d] TXAGC/PGA/GL_idx = 0x%x / 0x%x / 0x%x\n",
			       agc_cnt, tmp_txagc, tmp_pga, tmp_gl_idx);

			tmp_gain = _dpk_get_gainloss_8197g(dm, GAIN_CHK);
			tmp_loss = _dpk_get_gainloss_8197g(dm, LOSS_CHK);
			
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC-%d] G=%d.%02d, GL=%d.%02ddB\n",
			       agc_cnt, tmp_gain / 100, HALRF_ABS(0, tmp_gain) % 100,
			       (tmp_gain - tmp_loss) / 100, (tmp_gain - tmp_loss) % 100);

			if (DPK_PAS_DBG_8197G)
				_dpk_pas_read_8197g(dm, path);

			if (tmp_gl_idx == 0xa) /*GL < criterion*/
				i = 4;
			else if (tmp_gl_idx < 0x4) /*GL > criterion*/
				i = 3;
			else
				goout = 1;

			agc_cnt++;
			break;

		case 1: /*add PGA gain*/
			if (tmp_pga == 0x7 || tmp_gain >= -400) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA or Gain @ upper bound!!\n");
				limited_pga = 1;
			}
			else if (tmp_pga == 0x3)
				tmp_pga = tmp_pga + 2; /*avoid PGA gap*/
			else
				tmp_pga = tmp_pga + 1;

			if (limited_pga != 1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x0e000, tmp_pga);
				RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] PGA(+) = 0x%x\n",
				       tmp_pga);
				ODM_delay_us(5);
			}

			i = 5;
			break;

		case 2: /*reduce PGA gain*/
			if (tmp_pga == 0x0 || tmp_gain <= -600) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA or Gain @ lower bound!!\n");
				limited_pga = 1;
			}
			else if (tmp_pga == 0x5)
				tmp_pga = tmp_pga - 2; /*avoid PGA gap*/
			else
				tmp_pga = tmp_pga - 1;

			if (limited_pga != 1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x0e000, tmp_pga);
				RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] PGA(-) = 0x%x\n",
				       tmp_pga);
				ODM_delay_us(5);
			}

			i = 5;
			break;

		case 3: /*GL > criterion*/
			if (tmp_txagc == 0x00) {
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
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] TXAGC(-) = 0x%x\n",
			       tmp_txagc);

			ODM_delay_us(5);
			limited_pga = 0;

			i = 1;
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
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] TXAGC(+) = 0x%x\n",
			       tmp_txagc);

			ODM_delay_us(5);
			limited_pga = 0;

			i = 2;
			break;

		case 5: /*GL one-shot*/
			_dpk_one_shot_8197g(dm, GAIN_LOSS);

			tmp_gl_idx = _dpk_gainloss_result_8197g(dm, path);

			i = 0;
			break;

		default:
			goout = 1;
			break;
		}	
	} while (!goout && (agc_cnt < 6));

	return _dpk_adjust_pga_8197g(dm, path, tmp_txagc, tmp_pga, tmp_gl_idx);
}

u8 _dpk_gainloss_8197g(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 txagc_ori, txagc, gl_idx;

	txagc_ori = _dpk_rf_setting_8197g(dm, path);

	dpk_info->thermal_dpk[path] = _dpk_thermal_read_8197g(dm, path);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] S%d thermal = 0x%x\n", 
	       path, dpk_info->thermal_dpk[path]);

	ODM_delay_ms(1);

	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	/*tpg select*/
	odm_set_bb_reg(dm, R_0x1b80, MASKDWORD, 0x10000000 | ((dpk_info->dpk_bw - 2) << 25));

	RF_DBG(dm, DBG_RF_DPK, "[DPK] TPG select for %s\n",
	       (dpk_info->dpk_bw - 2) ? "20M" : "40M");

	_dpk_timing_sync_8197g(dm, path);

#if 1
	txagc = _dpk_pas_agc_8197g(dm, path, txagc_ori);
#else
	_dpk_auto_pga_8197g(dm, path);
	gl_idx = _dpk_gainloss_result_8197g(dm, path);
	txagc = txagc_ori - 0xa + gl_idx;
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f, txagc);
#endif
#if 0
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][GL] S%d RF_0x0 / 0x8f / GL_idx = 0x%x / 0x%x / %d\n",
	       path, odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, RFREG_MASK), gl_idx);
#endif
	return txagc;
}

u8 _dpk_lms_8197g(
	struct dm_struct *dm)
{
	u8 result;

	odm_write_1byte(dm, R_0x1b83, 0x00);		/*disable TPG_pattern*/
	odm_write_1byte(dm, R_0x1b23, 0x01);		/*enable dpd on*/
	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x020df0b8);
	odm_write_1byte(dm, R_0x1bca, 0x00);		/*default pattern*/
	odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x3f);	/*ItQt = 0*/
	odm_set_bb_reg(dm, R_0x1bcc, MASKHWORD, 0x0385);

	_dpk_one_shot_8197g(dm, DO_DPK);
	
	result = (u8)odm_get_bb_reg(dm, R_0x1bfc, BIT(1));
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] LMS fail bit = %x\n", result);

	odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x00);	/*ItQt = 1*/

	return result;
}

u8 _dpk_by_path_8197g(
	struct dm_struct *dm,
	u8 dpk_txagc,
	u8 path,
	u8 group)
{
	u8 result;
	s8 pwsf_idx = 0;

	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	pwsf_idx = dpk_txagc - 0x19;

	if (dm->cut_version == 0)
		odm_set_bb_reg(dm, R_0x1be8, 0x1F000000, pwsf_idx & 0x1f);
	else
		odm_set_bb_reg(dm, R_0x1be8, 0x7C000000, pwsf_idx & 0x1f);

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][DO_DPK] S%d TXAGC/PGA/pwsf_idx = 0x%x / 0x%x / 0x%x\n",
	       path, odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f),
	       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0x0e000),
	       pwsf_idx & 0x1f);

	_dpk_one_shot_8197g(dm, GAIN_LOSS);

	result = _dpk_pas_check_8197g(dm);

	if (DPK_PAS_DBG_8197G)
		_dpk_pas_read_8197g(dm, path);

	ODM_delay_us(10);

	_dpk_lms_8197g(dm);

	odm_write_1byte(dm, R_0x1b23, 0x03); /*dpd off*/
	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e018); /*use LUT SRAM data*/
	odm_set_bb_reg(dm, R_0x1bcc, MASKHWORD, 0x1902); /*bypass pa!=11*/

	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] fail bit = %x\n", result);

	return result;
}

boolean _dpk_lms_iq_check_8197g(
	struct dm_struct *dm,
	u8 addr,
	u32 reg_1bfc)
{
	u32 i_val = 0, q_val = 0;

	if (DPK_SRAM_IQ_DBG_8197G && (addr < 16))
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] 0x1bfc[%2d] = 0x%x\n", addr, reg_1bfc);

	i_val = (reg_1bfc & 0x003FF800) >> 11;
		q_val = reg_1bfc & 0x000007FF;

	if (((q_val & 0x400) >> 10) == 1)
		q_val = 0x800 - q_val;

	if ((addr == 0) && ((i_val*i_val + q_val*q_val) < 0x197a9)) {
		/* LMS (I^2 + Q^2) < -4dB happen*/
			RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT < -4dB happen, I=0x%x, Q=0x%x\n",
			       i_val, q_val);
			return 1;
	} else
		return 0;
	}

void _dpk_on_8197g(
	struct dm_struct *dm,
	u8 path)
{
	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	odm_write_1byte(dm, R_0x1b97, 0x77); /*pm disable*/
	odm_write_1byte(dm, R_0x1bcb, 0x00); /*PAS+LMS con disable*/
	odm_set_bb_reg(dm, R_0x1b20, BIT(25) | BIT(24), 0x1); /*enable DPD*/
	odm_set_bb_reg(dm, R_0x1be8, BIT(16), 0x0); /*gs from LMS result*/

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPD enable!!!\n\n", path);
}

void dpk_sram_read_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, addr;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Start =========\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		for (group = 0; group < DPK_GROUP_NUM_8197G; group++) {
			for (addr = 0; addr < 16; addr++)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read S%d[%d] even[%02d]= 0x%x\n",
				       path, group, addr,
				       dpk_info->lut_2g_even[path][group][addr]);

			for (addr = 0; addr < 16; addr++)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read S%d[%d]  odd[%02d]= 0x%x\n",
				       path, group, addr,
				       dpk_info->lut_2g_odd[path][group][addr]);
}
		}
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Finish =========\n");
}

u8 _dpk_lut_sram_read_8197g(
	void *dm_void,
	u8 group,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, i;
	u32 reg_1bdc = 0, reg_1bfc = 0;

	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	odm_write_1byte(dm, R_0x1b08, 0x80);

	/*even*/
	odm_write_1byte(dm, R_0x1bd6, 0x22);

	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);

		addr = (i - 1) / 2;
		if ((addr == 0) && _dpk_lms_iq_check_8197g(dm, addr, reg_1bfc))
			return 0;
		else
			dpk_info->lut_2g_even[path][group][addr] = reg_1bfc;
		}

	/*odd*/
	odm_write_1byte(dm, R_0x1bd6, 0x23);

	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);

		addr = (i - 1) / 2;
		if ((addr == 0) && _dpk_lms_iq_check_8197g(dm, addr, reg_1bfc))
			return 0;
		else
			dpk_info->lut_2g_odd[path][group][addr] = reg_1bfc;
		}

	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);

	return 1;
}

void _dpk_lut_sram_write_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, path;
	u32 reg_1bdc_even, reg_1bdc_odd, temp1, temp2, temp3;

	reg_1bdc_even = 0xc0000000;
	reg_1bdc_odd = 0x80000080;

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
		/*write_even*/
		for (addr = 0; addr < 16; addr++) {
			temp1 = dpk_info->lut_2g_even[path][0][addr];
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_even | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));

#if (DPK_SRAM_write_DBG_8197G)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d] even[%2d]= 0x%x\n",
			       path, 0, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));
#endif
		}

		/*write_odd*/
		for (addr = 0; addr < 16; addr++) {
			temp1 = dpk_info->lut_2g_odd[path][0][addr];
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_odd | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));

#if (DPK_SRAM_write_DBG_8197G)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d]  odd[%2d]= 0x%x\n",
			       path, 0, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));
#endif
		}

		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);

		if (dm->cut_version == 0)
			odm_set_bb_reg(dm, R_0x1be8, 0x1F000000, dpk_info->pwsf_2g[path][0]);
		else
			odm_set_bb_reg(dm, R_0x1be8, 0x7F000000, dpk_info->pwsf_2g[path][0]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S%d[%d] pwsf = 0x%x\n",
		       path, group, dpk_info->pwsf_2g[path][group]);
#endif
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S%d[%d] 0x1beb = 0x%x\n",
		       path, 0, odm_get_bb_reg(dm, R_0x1beb, MASKDWORD));
	}
}

void _dpk_lut_sram_default_8197g(
	void *dm_void,
	u8 group,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	u8 i;

	odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d SRAM write default!!!\n", path);

	/*even*/
	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xd0000000 | i);
	}

	/*odd*/
	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x90000080 | i);
	}

	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
}

u8 _dpk_check_fail_8197g(
	struct dm_struct *dm,
	boolean is_fail,
	u8 path,
	u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 result = 0;

	if (!is_fail && _dpk_lut_sram_read_8197g(dm, group, path)) {
		if (dm->cut_version == 0)
			dpk_info->pwsf_2g[path][group] =
				(u8)odm_get_bb_reg(dm, R_0x1be8, 0x1F000000);
		else
			dpk_info->pwsf_2g[path][group] =
				(u8)odm_get_bb_reg(dm, R_0x1be8, 0x7F000000);
		dpk_info->dpk_result[path][group] = 1;
		result = 1;
	}

	return result;
}

void _dpk_result_reset_8197g(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group;

	dpk_info->dpk_path_ok = 0;

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		for (group = 0; group < DPK_GROUP_NUM_8197G; group++) {
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

void _dpk_calibrate_8197g(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 dpk_fail = 1, dpk_txagc = 0;
	u8 retry_cnt;

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] =========== S%d DPK Start ===========\n", path);

	for (retry_cnt = 0; retry_cnt < 1; retry_cnt++) {

		dpk_txagc = _dpk_gainloss_8197g(dm, path);

		ODM_delay_ms(1);

		dpk_fail = _dpk_by_path_8197g(dm, dpk_txagc, path, 0);

		if (_dpk_check_fail_8197g(dm, dpk_fail, path, 0))
			break;
	}

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] =========== S%d DPK Finish ==========\n", path);

	if (dpk_info->dpk_result[path][0])
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);
}

void _dpk_path_select_8197g(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

#if (DPK_DO_PATH_A)
	
	_dpk_calibrate_8197g(dm, RF_PATH_A);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_A)) >> RF_PATH_A)
	_dpk_on_8197g(dm, RF_PATH_A);
#endif

#if (DPK_DO_PATH_B)
	_dpk_calibrate_8197g(dm, RF_PATH_B);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_B)) >> RF_PATH_B)
	_dpk_on_8197g(dm, RF_PATH_B);
#endif
}

void _dpk_result_summary_8197g(
	struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		for (group = 0; group < DPK_GROUP_NUM_8197G; group++) {
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

#if (DPK_SRAM_read_DBG_8197G)
	dpk_sram_read_8197g(dm);
#endif	
}

void dpk_reload_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path;

	_dpk_lut_sram_write_8197g(dm);

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));

		if ((dpk_info->dpk_path_ok & BIT(path)) >> path)
			_dpk_on_8197g(dm, path);
		else
			odm_set_bb_reg(dm, R_0x1b20, 0x07000000, 0x7);
	}

	dpk_enable_disable_8197g(dm);
}

void do_dpk_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	u32 bb_reg_backup[DPK_BB_REG_NUM_8197G];
	u32 rf_reg_backup[DPK_RF_REG_NUM_8197G][DPK_RF_PATH_NUM_8197G];

	u32 bb_reg[DPK_BB_REG_NUM_8197G] = {
		R_0x520, R_0x824, R_0x180c, R_0x410c, R_0x1d58,
		R_0x1a00, R_0x1864, R_0x4164, R_0x1d70, R_0x1e70,
		R_0x18a4, R_0x41a4, R_0x1e7c};
	u32 rf_reg[DPK_RF_REG_NUM_8197G] = {RF_0xdf, RF_0x8f};

	if (dm->ext_pa) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Skip DPK due to ext_PA exist!!\n");
		return;
	}

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] ****** 8197G DPK Start (Ver: %s), Cv: %d ******\n",
	       DPK_VER_8197G, dm->cut_version);

	_backup_mac_bb_registers_8197g(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8197G);
	_backup_rf_registers_8197g(dm, rf_reg, rf_reg_backup);

	_dpk_information_8197g(dm);

	_dpk_mac_bb_setting_8197g(dm);
	_dpk_pre_setting_8197g(dm);
	_dpk_afe_setting_8197g(dm, true);

	_dpk_result_reset_8197g(dm);
	_dpk_path_select_8197g(dm);
	_dpk_result_summary_8197g(dm);

	_dpk_afe_setting_8197g(dm, false);

	_reload_rf_registers_8197g(dm, rf_reg, rf_reg_backup);
	_reload_mac_bb_registers_8197g(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8197G);
	dpk_enable_disable_8197g(dm);
}

void dpk_enable_disable_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path;

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
			odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));

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

void dpk_track_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	struct _hal_rf_ *rf = &dm->rf_table;

	u8 is_increase, i = 0, k = 0, path, pwsf[2];
	u8 thermal_dpk_avg_count = 0, thermal_value[2] = {0};
	u32 thermal_dpk_avg[2] = {0};
	s8 delta_dpk[2];

	if ((dpk_info->thermal_dpk[0] == 0) && (dpk_info->thermal_dpk[1] == 0)) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK_track] Bypass DPK tracking!!!!\n");
			return;
	} else if (dm->cut_version == 0) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK_track] No DPK tracking for A-Cv!!!!\n");
			return;
	} else	
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "=================== [8197G DPK_track] ===================\n");

	/*get thermal meter*/
	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		thermal_value[path] = _dpk_thermal_read_8197g(dm, path);

		dpk_info->thermal_dpk_avg[path][dpk_info->thermal_dpk_avg_index] =
		thermal_value[path];
	}
	dpk_info->thermal_dpk_avg_index++;

	/*Average times */
	if (dpk_info->thermal_dpk_avg_index == THERMAL_DPK_AVG_NUM)
		dpk_info->thermal_dpk_avg_index = 0;

	for (i = 0; i < THERMAL_DPK_AVG_NUM; i++) {
		if (dpk_info->thermal_dpk_avg[0][i] ||
		    dpk_info->thermal_dpk_avg[1][i]) {
			thermal_dpk_avg[0] += dpk_info->thermal_dpk_avg[0][i];
			thermal_dpk_avg[1] += dpk_info->thermal_dpk_avg[1][i];
			thermal_dpk_avg_count++;
		}
	}

	/*Calculate Average ThermalValue after average enough times*/
	if (thermal_dpk_avg_count) {

		for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
			thermal_value[path] = (u8)(thermal_dpk_avg[path] / thermal_dpk_avg_count);

			RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
			       "[DPK_track] S%d Thermal now = %d (DPK @ %d)\n", path,
			       thermal_value[path], dpk_info->thermal_dpk[path]);
		}
	}

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		delta_dpk[path] = thermal_value[path] - dpk_info->thermal_dpk[path];

		pwsf[path] = (dpk_info->pwsf_2g[path][0] + delta_dpk[path]) & 0x7F;

	RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
	       "[DPK_track] S%d ori_pwsf = 0x%x, pwsf_diff = %d\n", path,
	       dpk_info->pwsf_2g[path][0],
	       delta_dpk[path] > 128 ? delta_dpk[path] - 256 : delta_dpk[path]);
 	}

	if (rf->is_dpk_in_progress || dm->rf_calibrate_info.is_iqk_in_progress ||
		rf->is_tssi_in_progress)
		return;

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {
		if (pwsf[path] != dpk_info->pre_pwsf[path]) {
			odm_set_bb_reg(dm, R_0x1b00, 0x0000000f, 0x8 | (path << 1));
			odm_set_bb_reg(dm, R_0x1be8, 0x7f000000, pwsf[path]);
			dpk_info->pre_pwsf[path] = pwsf[path];
			RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
			       "[DPK_track] S%d new pwsf is 0x%x, 0x1be8=0x%x\n",
			       path, dpk_info->pre_pwsf[path],
			       odm_get_bb_reg(dm, R_0x1be8, MASKDWORD));
		} else
			RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
			       "[DPK_track] S%d pwsf unchanged (0x%x)\n",
			       path, dpk_info->pre_pwsf[path]);
	}
}

void dpk_info_by_8197g(
	void *dm_void,
	u32 *_used,
	char *output,
	u32 *_out_len)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u32 used = *_used;
	u32 out_len = *_out_len;
	u8 path, addr;

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = %d / %d\n",
		 "S0 DC (I/Q)", dpk_info->dc_i[0], dpk_info->dc_q[0]);

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = %d / %d\n",
		 "S0 Corr (idx/val)", dpk_info->corr_idx[0], dpk_info->corr_val[0]);

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = %d / %d\n",
		 "S1 DC (I/Q)", dpk_info->dc_i[1], dpk_info->dc_q[1]);

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = %d / %d\n",
		 "S1 Corr (idx/val)", dpk_info->corr_idx[1], dpk_info->corr_val[1]);

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = 0x%x / 0x%x\n",
		 "DPK PWSF (path)", dpk_info->pwsf_2g[0][0] >> 2, dpk_info->pwsf_2g[1][0] >> 2);

	PDM_SNPF(out_len, used, output + used, out_len - used, " %-25s = 0x%x / 0x%x\n",
		 "PWSF now (path)", dpk_info->pre_pwsf[0] >> 2, dpk_info->pre_pwsf[1] >> 2);

	PDM_SNPF(out_len, used, output + used, out_len - used,
		 "\n==============[ SRAM Read Start ]==============\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8197G; path++) {

		PDM_SNPF(out_len, used, output + used, out_len - used, "\n");

		for (addr = 0; addr < 16; addr++)
			PDM_SNPF(out_len, used, output + used, out_len - used,
				 " Read S%d even[%02d]= 0x%x\n",
		 		 path, addr, dpk_info->lut_2g_even[path][0][addr]);

		for (addr = 0; addr < 16; addr++)
			PDM_SNPF(out_len, used, output + used, out_len - used,
				 " Read S%d  odd[%02d]= 0x%x\n",
		 		 path, addr, dpk_info->lut_2g_odd[path][0][addr]);
	}

	PDM_SNPF(out_len, used, output + used, out_len - used,
		 "\n==============[ SRAM Read Finish ]==============\n");
}

#endif
