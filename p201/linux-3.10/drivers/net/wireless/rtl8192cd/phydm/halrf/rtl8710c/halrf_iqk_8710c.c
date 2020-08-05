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

#if (RTL8710C_SUPPORT == 1)

/*@---------------------------Define Local Constant---------------------------*/

void do_iqk_8710c(void *dm_void, u8 delta_thermal_index, u8 thermal_value,
		  u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	dm->rf_calibrate_info.thermal_value_iqk = thermal_value;
	halrf_segment_iqk_trigger(dm, true, iqk->segment_iqk);
}

#if 1

void _iqk_fill_lok_8710c(void *dm_void, u8 max)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8  i;
	u32 temp;
	
	temp = odm_get_rf_reg(dm, RF_PATH_A, 0x8, MASK20BITS);
	odm_set_rf_reg(dm, RF_PATH_A, 0x57, BIT(11), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, BIT(3), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, BIT(6) | BIT(5) | BIT(4), 0x2);
	for (i = 0x0; i < max; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xf, i);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8, MASK20BITS, temp);
	}
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, BIT(3), 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, BIT(6) | BIT(5) | BIT(4), 0x0);	
}

void _iqk_rf_set_check_8710c(struct dm_struct *dm, u8 path, u16 add, u32 data)
{
	u32 i;

	odm_set_rf_reg(dm, (enum rf_path)path, add, MASK20BITS, data);

	for (i = 0; i < 100; i++) {
		if (odm_get_rf_reg(dm, (enum rf_path)path,
				   add, MASK20BITS) == data)
			break;

		ODM_delay_us(10);
		odm_set_rf_reg(dm, (enum rf_path)path, add, MASK20BITS, data);
	}
}

void _iqk_fill_iqk_report_8710c(void *dm_void, u8 ch)
{

}

void _iqk_fail_count_8710c(void *dm_void)
{

}

void _iqk_iqk_fail_report_8710c(struct dm_struct *dm)
{

}

void _iqk_bp_macbb_8710c(struct dm_struct *dm, u32 *mac_bp,
			 u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	for (i = 0; i < MAC_NUM_8710C; i++)
		mac_bp[i] = odm_read_4byte(dm, bp_mac_reg[i]);

	for (i = 0; i < BB_NUM_8710C; i++)
		bb_bp[i] = odm_read_4byte(dm, bp_bb_reg[i]);
}

void _iqk_bp_rf_8710c(struct dm_struct *dm, u32 rf_bp[][SS_8710C],
		      u32 *bp_reg)
{
	u8 i, s;

	for (s = 0; s < SS_8710C; s++) {
		for (i = 0; i < RF_NUM_8710C; i++) {
			rf_bp[i][s] = odm_get_rf_reg(dm, (enum rf_path)s,
						     bp_reg[i], MASK20BITS);
		}
	}
}

void _iqk_set_afe_8710c(struct dm_struct *dm, boolean do_iqk)
{
	u8 i;

	if (do_iqk) {
		odm_write_4byte(dm, 0xe70, 0x03c00016);
	} else {
		odm_write_4byte(dm, 0xe70, 0x01c00016);
	}
}

void _iqk_reload_macbb_8710c(struct dm_struct *dm, u32 *mac_bp,
			     u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	/*toggle IGI*/
	odm_write_1byte(dm, 0xc50, 0x50);

	for (i = 0; i < MAC_NUM_8710C; i++)
		odm_write_4byte(dm, bp_mac_reg[i], mac_bp[i]);
	for (i = 0; i < BB_NUM_8710C; i++)
		odm_write_4byte(dm, bp_bb_reg[i], bb_bp[i]);
}

void _iqk_reload_rf_8710c(struct dm_struct *dm, u32 *reg,
			   u32 data[][SS_8710C])
{
	u32 i;

	for (i = 0; i < RF_NUM_8710C; i++)
		odm_set_rf_reg(dm, RF_PATH_A, reg[i], 0xfffff, data[i][0]);

}

void _iqk_backup_iqk_8710c_subfunction(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k;

	iqk->iqk_channel[1] = iqk->iqk_channel[0];
	for (i = 0; i < SS_8710C; i++) {
		iqk->lok_idac[1][i] = iqk->lok_idac[0][i];
		iqk->rxiqk_agc[1][i] = iqk->rxiqk_agc[0][i];
		iqk->bypass_iqk[1][i] = iqk->bypass_iqk[0][i];
		iqk->rxiqk_fail_code[1][i] = iqk->rxiqk_fail_code[0][i];
		for (j = 0; j < 2; j++) {
			iqk->iqk_fail_report[1][i][j] =
						iqk->iqk_fail_report[0][i][j];
			for (k = 0; k < 8; k++) {
				iqk->iqk_cfir_real[1][i][j][k] =
						iqk->iqk_cfir_real[0][i][j][k];
				iqk->iqk_cfir_imag[1][i][j][k] =
						iqk->iqk_cfir_imag[0][i][j][k];
			}
		}
	}
}

void _iqk_backup_iqk_8710c(struct dm_struct *dm, u8 step)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j;

	switch (step) {
	case 0:
		_iqk_backup_iqk_8710c_subfunction(dm);
		for (i = 0; i < SS_8710C; i++) {
			iqk->rxiqk_fail_code[0][i] = 0x0;
			iqk->rxiqk_agc[0][i] = 0x0;
			for (j = 0; j < 2; j++) {
				iqk->iqk_fail_report[0][i][j] = true;
				iqk->gs_retry_count[0][i][j] = 0x0;
			}
			for (j = 0; j < 3; j++)
				iqk->retry_count[0][i][j] = 0x0;
		}
		/*backup channel*/
		iqk->iqk_channel[0] = iqk->rf_reg18;
		break;
	case 1: /*LOK backup*/
		iqk->lok_idac[0][0] = odm_get_rf_reg(dm, RF_PATH_A,
							RF_0x58, MASK20BITS);
		break;
	case 2: /*TXIQK backup*/
	case 3: /*RXIQK backup*/
//		phydm_get_iqk_cfir(dm, (step - 2), path, false);
		break;
	}
}

void _iqk_reload_iqk_setting_8710c(struct dm_struct *dm, u8 ch,
				   u8 reload_idx
				   /*1: reload TX, 2: reload LO, TX, RX*/)
{

}

void _iqk_set_rfe_8710c(struct dm_struct *dm, boolean ext_pa_on)
{
#if 0
	if (ext_pa_on) {
		/*RFE setting*/
		odm_write_4byte(dm, 0xcb0, 0x77777777);
		odm_write_4byte(dm, 0xcb4, 0x00007777);
		odm_write_4byte(dm, 0xcbc, 0x0000083B);
		odm_write_4byte(dm, 0xeb0, 0x77777777);
		odm_write_4byte(dm, 0xeb4, 0x00007777);
		odm_write_4byte(dm, 0xebc, 0x0000083B);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]external PA on!!!!\n");
	} else {
		/*RFE setting*/
		odm_write_4byte(dm, 0xcb0, 0x77777777);
		odm_write_4byte(dm, 0xcb4, 0x00007777);
		odm_write_4byte(dm, 0xcbc, 0x00000100);
		odm_write_4byte(dm, 0xeb0, 0x77777777);
		odm_write_4byte(dm, 0xeb4, 0x00007777);
		odm_write_4byte(dm, 0xebc, 0x00000100);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]external PA off!!!!\n");
	}
#endif
}

void _iqk_set_macbb_8710c(struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, REG_TXPAUSE, 0xff);
	/*3-wire off*/
	odm_set_bb_reg(dm, 0x88c, 0xf00000, 0xf);
	/*RX CCA off*/
	odm_set_bb_reg(dm, 0xc04, 0xf0, 0x0);
	/*AFE to RFK mode*/
	odm_set_bb_reg(dm, 0xc08, BIT(19), 0x1);
	/*Release DAC BUF rst*/
	odm_set_bb_reg(dm, 0x874, BIT(21), 0x1);
}

void _iqk_lok_setting_8710c(struct dm_struct *dm, u8 i)
{
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0xdf, BIT(1), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, BIT(3), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x56, 0xfff, 0xe08 | (i << 5));
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xfffff, 0x20 | i );
//	RF_DBG(dm, DBG_RF_IQK, "[IQK]RF0x56=0x%x\n",
//		odm_get_rf_reg(dm, RF_PATH_A, 0x56, MASK20BITS));
	odm_set_rf_reg(dm, RF_PATH_A, 0x57, BIT(11), 0x1);
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x808000);
	/*TXK step = 1*/
	odm_write_4byte(dm, 0xe30, 0x1801bc1c);
	odm_write_4byte(dm, 0xe34, 0x38008c1c);
	odm_write_4byte(dm, 0xe38, 0x821403e8);
	odm_write_4byte(dm, 0xe3c, 0x68160c06);
	odm_write_4byte(dm, 0xe40, 0x01007c00);
	odm_write_4byte(dm, 0xe44, 0x01004800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
	odm_write_4byte(dm, 0xe4c, 0x00462911);
}

void _iqk_txk_setting_8710c(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0xdf, BIT(1), 0x1);
//	odm_set_rf_reg(dm, RF_PATH_A, 0xef, BIT(3), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x56, 0xfff, 0xee8);
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x808000);
	odm_write_4byte(dm, 0xe30, 0x18008c1c);
	odm_write_4byte(dm, 0xe34, 0x38008c1c);
	odm_write_4byte(dm, 0xe38, 0x821403e8);
	odm_write_4byte(dm, 0xe3c, 0x68160c06);
	odm_write_4byte(dm, 0xe40, 0x01007c00);
	odm_write_4byte(dm, 0xe44, 0x01004800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
	odm_write_4byte(dm, 0xe4c, 0x00462911);
}

u32 _iqk_rxk1_setting_8710c(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0xdf, BIT(1), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x56, 0xfff, 0xee8);
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x808000);
	odm_write_4byte(dm, 0xe30, 0x18008c1c);
	odm_write_4byte(dm, 0xe34, 0x38008c1c);
	odm_write_4byte(dm, 0xe38, 0x821603e8);
	odm_write_4byte(dm, 0xe3c, 0x68160c06);
	odm_write_4byte(dm, 0xe40, 0x01007c00);
	odm_write_4byte(dm, 0xe44, 0x01004800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
	odm_write_4byte(dm, 0xe4c, 0x0046a911);
}

void _iqk_rxk2_setting_8710c(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0xdf, BIT(1), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x56, 0xfff, 0x028);
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x808000);
	odm_write_4byte(dm, 0xe30, 0x38008c1c);
	odm_write_4byte(dm, 0xe34, 0x1800cc1c);
	odm_write_4byte(dm, 0xe38, 0x821603e8);
	odm_write_4byte(dm, 0xe3c, 0x68170408);
	odm_write_4byte(dm, 0xe44, 0x01004800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
	odm_write_4byte(dm, 0xe4c, 0x0046a911);
}


void
_iqk_check_lok_8710c(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 delay_count = 0x0;
	u32 reg_eac;
	
	while (delay_count < 100) {
		delay_count++;
		ODM_delay_ms(1);
		reg_eac = odm_get_bb_reg(dm, 0xeac, MASKDWORD);
		if (reg_eac & BIT(26))
			break;
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = %d\n", delay_count);
}

boolean
_iqk_check_txk_8710c(struct dm_struct *dm, u8 idx)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean notready = true, fail = true;
	u32 delay_count = 0x0;
	u32 reg_eac, reg_e94, reg_e9c, temp = 0x0;
	/*cmd=0:TXIQK, 1:RXIQK*/

	while (delay_count < 100) {
		delay_count++;
		ODM_delay_ms(1);
		reg_eac = odm_get_bb_reg(dm, 0xeac, MASKDWORD);
		if (reg_eac & BIT(26))
			break;
	}
	reg_e94 = odm_get_bb_reg(dm, 0xe94, MASKDWORD);
	reg_e9c = odm_get_bb_reg(dm, 0xe9c, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK, "[IQK] 0xeac = 0x%x\n", reg_eac);
	RF_DBG(dm, DBG_RF_IQK, "[IQK] 0xe94 = 0x%x, 0xe9c = 0x%x\n", reg_e94,
	       reg_e9c);
	/*monitor image power before & after IQK*/
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK] 0xe90(before IQK)= 0x%x, 0xe98(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xe90, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe98, MASKDWORD));

	fail = (boolean)(reg_eac | BIT(28));
	RF_DBG(dm, DBG_RF_IQK, "[IQK] fail = %d\n", fail);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = %d!!\n", delay_count);

	if ((!fail) && (idx == TXIQK)) {
		iqk->txxy[0][0] = (reg_e94 & 0x3FF0000) >> 16;
		iqk->txxy[0][1] = (reg_e9c & 0x3FF0000)>> 16;
	}

	if ((!fail) && (idx == RXIQK1)) {
		temp = 0x80007c00 | (reg_e94 & 0x3FF0000);
		temp = temp | (reg_e9c & 0x3FF0000)>> 16;
		odm_write_4byte(dm, 0xe40, temp);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RXK1 0xe40 = 0x%x!!\n", temp);
	}
	return fail;
}

boolean
_iqk_check_rxk_8710c(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean notready = true, fail = true;
	u32 delay_count = 0x0;
	u32 reg_ea4, reg_eac;

	while (delay_count < 100) {
		delay_count++;
		ODM_delay_ms(1);
		reg_eac = odm_get_bb_reg(dm, 0xeac, MASKDWORD);
		if (reg_eac & BIT(26))
			break;
	}
	reg_ea4 = odm_get_bb_reg(dm, 0xea4, MASKDWORD);
	reg_eac = odm_get_bb_reg(dm, 0xeac, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK, "[IQK] 0xeac = 0x%x\n", reg_eac);
	RF_DBG(dm, DBG_RF_IQK, "[IQK] 0xea4 = 0x%x, 0xeac = 0x%x\n", reg_ea4,
	       reg_eac);
	/*monitor image power before & after IQK*/
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK] 0xea0(before IQK)= 0x%x, 0xea8(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xea0, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xea8, MASKDWORD));

	fail = (boolean)reg_eac | BIT(27);
	RF_DBG(dm, DBG_RF_IQK, "[IQK] fail = %d\n", fail);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = %d\n", delay_count);
	if (!fail) {
		iqk->rxxy[0][0] = (reg_ea4 & 0x3FF0000) >> 16;
		iqk->rxxy[0][1] = (reg_eac & 0x3FF0000)>> 16;
	}
	return fail;
}

#if 0
boolean
_iqk_rxk_gsearch_fail_8710c(struct dm_struct *dm, u8 path, u8 step)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD = 0x0, rf_reg0, tmp, bb_idx;
	u8 IQMUX[4] = {0x9, 0x12, 0x1b, 0x24};
	u8 idx;

	if (step == RXIQK1) {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d RXIQK GainSearch ============\n",
		       path);
		IQK_CMD = 0xf8000208 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
		       step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(IQK_DELAY_8710C);
		fail = _iqk_check_cal_8710c(dm, path, 0x1);
	} else if (step == RXIQK2) {
		for (idx = 0; idx < 4; idx++) {
			if (iqk->tmp1bcc == IQMUX[idx])
				break;
		}
		odm_write_4byte(dm, 0x1b00, 0xf8000008 | path << 1);
		odm_write_4byte(dm, 0x1bcc, iqk->tmp1bcc);

		IQK_CMD = 0xf8000308 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
		       step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(IQK_DELAY_8710C);
		fail = _iqk_check_cal_8710c(dm, path, 0x1);

		rf_reg0 = odm_get_rf_reg(dm, (enum rf_path)path,
					 RF_0x0, MASK20BITS);
		odm_write_4byte(dm, 0x1b00, 0xf8000008 | path << 1);
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]S%d RF0x0=0x%x tmp1bcc=0x%x idx=%d 0x1b3c=0x%x\n",
		       path, rf_reg0, iqk->tmp1bcc, idx,
		       odm_read_4byte(dm, 0x1b3c));
		tmp = (rf_reg0 & 0x1fe0) >> 5;
		iqk->lna_idx = tmp >> 5;
		bb_idx = tmp & 0x1f;

		if (bb_idx == 0x1) {
			if (iqk->lna_idx != 0x0)
				iqk->lna_idx--;
			else if (idx != 3)
				idx++;
			else
				iqk->isbnd = true;
			fail = true;
		} else if (bb_idx == 0xa) {
			if (idx != 0)
				idx--;
			else if (iqk->lna_idx != 0x7)
				iqk->lna_idx++;
			else
				iqk->isbnd = true;
			fail = true;
		} else {
			fail = false;
		}

		if (iqk->isbnd)
			fail = false;

		iqk->tmp1bcc = IQMUX[idx];

		if (fail) {
			odm_write_4byte(dm, 0x1b00, 0xf8000008 | path << 1);
			tmp = (odm_read_4byte(dm, 0x1b24) & 0xffffe3ff) |
				(iqk->lna_idx << 10);
			odm_write_4byte(dm, 0x1b24, tmp);
		}
	}
	return fail;
}
#endif

void
_lok_one_shot_8710c(struct dm_struct *dm)
{

	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]===LOK===\n");
	odm_write_4byte(dm, 0xe48, 0xf9000800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
	_iqk_check_lok_8710c(dm);
	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]RF0x56=0x%x, RF0x58=0x%x\n",
		odm_get_rf_reg(dm, RF_PATH_A, 0x56, MASK20BITS),
		odm_get_rf_reg(dm, RF_PATH_A, 0x58, MASK20BITS));
}

boolean
_iqk_one_shot_8710c(void *dm_void, u8 idx)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 delay_count = 0;
	boolean fail = true;
	u32 IQK_CMD = 0x0, tmp;

	if (idx == TXIQK)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]===TXK===\n");
	else if (idx == RXIQK1)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]=== RXK STEP1===\n");
	else
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]===RXK STEP2===\n");


	odm_write_4byte(dm, 0xe48, 0xf9000800);
	odm_write_4byte(dm, 0xe48, 0xf8000800);
//	ODM_delay_ms(IQK_DELAY_8710C);
	if (idx == TXIQK || idx == RXIQK1)
		fail = _iqk_check_txk_8710c(dm, idx);
	else
		fail = _iqk_check_rxk_8710c(dm);		

	odm_set_bb_reg(dm, 0xe28, 0xffffff00, 0x0);
	if (idx == RXIQK2) {
		RF_DBG(dm, DBG_RF_IQK,"[IQK]RF0x0 = 0x%x, RF0x56 = 0x%x\n",
		       odm_get_rf_reg(dm, RF_PATH_A, RF_0x0, MASK20BITS),
		       odm_get_rf_reg(dm, RF_PATH_A, RF_0x56, MASK20BITS));
	}

	if (idx == TXIQK)
		iqk->iqk_fail_report[0][0][TXIQK] = fail;
	else
		iqk->iqk_fail_report[0][0][RXIQK] = fail;

	return fail;
}

boolean
_iqk_rx_iqk_by_path_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true, gonext, gs_limit;

#if 1
	switch (iqk->rxiqk_step) {
	case 0: /*gain search_RXK1*/
#if 0
		_iqk_rxk1_setting_8710c(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_rxk_gsearch_fail_8710c(dm, path, RXIQK1);
			if (KFAIL && iqk->gs_retry_count[0][path][0] < 2) {
				iqk->gs_retry_count[0][path][0]++;
			} else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 0;
				iqk->rxiqk_step = 4;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
		halrf_iqk_xym_read(dm, path, 0x2);
#else
	iqk->rxiqk_step++;
#endif
		break;
	case 1: /*gain search_RXK2*/
#if 0
		_iqk_rxk2_setting_8710c(dm, path, true);
		iqk->isbnd = false;
		while (1) {
			KFAIL = _iqk_rxk_gsearch_fail_8710c(dm, path, RXIQK2);
			gs_limit = (iqk->gs_retry_count[0][path][1] <
				rxiqk_gs_limit);
			if (KFAIL && gs_limit) {
				iqk->gs_retry_count[0][path][1]++;
			} else {
				iqk->rxiqk_step++;
				break;
			}
		}
		halrf_iqk_xym_read(dm, path, 0x3);
#else
	iqk->rxiqk_step++;
#endif
		break;
	case 2: /*RXK1*/
#if 1
		_iqk_rxk1_setting_8710c(dm);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8710c(dm, RXIQK1);
			if (KFAIL && iqk->retry_count[0][0][RXIQK1] < 2) {
				iqk->retry_count[0][0][RXIQK1]++;
			} else if (KFAIL) {
				iqk->rxiqk_fail_code[0][0] = 1;
				iqk->rxiqk_step = 4;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
//		halrf_iqk_xym_read(dm, path, 0x4);
#else
	iqk->rxiqk_step++;
#endif
		break;
	case 3: /*RXK2*/
		_iqk_rxk2_setting_8710c(dm);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8710c(dm, RXIQK2);
			if (KFAIL && iqk->retry_count[0][0][RXIQK2] < 2) {
				iqk->retry_count[0][0][RXIQK2]++;
			} else if (KFAIL) {
				iqk->rxiqk_fail_code[0][0] = 2;
				iqk->rxiqk_step = 4;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
//		halrf_iqk_xym_read(dm, path, 0x0);
		break;
	}
	return KFAIL;
#endif
}

void _iqk_summy_report_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]===IQK summary ===\n");
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXK_fail = %d\n",
	       iqk->iqk_fail_report[0][RF_PATH_A][TXIQK]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK_fail = %d\n",
	       iqk->iqk_fail_report[0][RF_PATH_A][RXIQK]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXK_retry = %d\n",
	       iqk->retry_count[0][RF_PATH_A][TXIQK]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK1_retry = %d, S0_RXK2_retry = %d\n",
	       iqk->retry_count[0][RF_PATH_A][RXIQK1],
	       iqk->retry_count[0][RF_PATH_A][RXIQK2]);
#if 0
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_GS1_retry = %d, S0_GS2_retry = %d\n",
	       iqk->gs_retry_count[0][RF_PATH_A][0],
	       iqk->gs_retry_count[0][RF_PATH_A][1]);
#endif
}

void _iqk_lok_by_pad_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 lok_pad_idx[3] = {7, 3, 1};
	u8 i = 0, max = 0;

	for (i = 0; i < 3; i++) {
		_iqk_lok_setting_8710c(dm, lok_pad_idx[i]);
		_lok_one_shot_8710c(dm);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]PAD=0x%x\n", lok_pad_idx[i]);
		if (i == 0)
			max = 0x10;
		else
			max = lok_pad_idx[i] + 1;
		_iqk_fill_lok_8710c(dm, max);
	}
}

void _iqk_rxiqk_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true;
	u8 c = 0;

	while (c < 100) {
		c++;
		KFAIL = _iqk_rx_iqk_by_path_8710c(dm);
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]RXK KFail = 0x%x\n", KFAIL);
		if (iqk->rxiqk_step == RXK_STEP_8710C) {
			iqk->iqk_step++;
			iqk->rxiqk_step = 0;
			if (KFAIL)
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK]S%dRXK fail code: %d!!!\n",
				       iqk->rxiqk_fail_code[0][0]);
			break;
		}
	}
	iqk->kcount++;
}

void
_iqk_update_txiqc_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 oldval_0, X, TX0_A, reg;
	s32 Y, TX0_C;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]===update TXIQC ===\n");
	oldval_0 = (odm_get_bb_reg(dm, 0xc80, MASKDWORD) >> 22) & 0x3FF;

	X = iqk->txxy[0][0];
	if ((X & 0x00000200) != 0)
		X = X | 0xFFFFFC00;
	TX0_A = (X * oldval_0) >> 8;
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK] X = 0x%x, TX_A = 0x%x, default=0x%x\n", X,
	       TX0_A, oldval_0);
	odm_set_bb_reg(dm, 0xc80, 0x3FF, TX0_A);
	odm_set_bb_reg(dm, 0xc4c, BIT(31), ((X * oldval_0 >> 7) & 0x1));
	Y = iqk->txxy[0][1];
	if ((Y & 0x00000200) != 0)
		Y = Y | 0xFFFFFC00;
	TX0_C = (Y * oldval_0) >> 8;
	RF_DBG(dm, DBG_RF_IQK, "[IQK] Y = 0x%x, TX_C = 0x%x\n", Y,
	       TX0_C);
	odm_set_bb_reg(dm, 0xc94, 0xF0000000, ((TX0_C & 0x3C0) >> 6));
	odm_set_bb_reg(dm, 0xc80, 0x003F0000, (TX0_C & 0x3F));
	odm_set_bb_reg(dm, 0xc4c, BIT(29), ((Y * oldval_0 >> 7) & 0x1));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0xc80 = 0x%x\n",
	       odm_get_bb_reg(dm, 0xc80, MASKDWORD));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0xc94 = 0x%x\n",
	       odm_get_bb_reg(dm, 0xc94, MASKDWORD));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0xc4c = 0x%x\n",
	       odm_get_bb_reg(dm, 0xc4c, MASKDWORD));
}

void
_iqk_update_rxiqc_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 reg = 0x0;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]===update RXIQC ===\n");
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]RX_A = 0x%x, RX_B = 0x%x\n", iqk->rxxy[0], iqk->rxxy[1]);
	reg = iqk->rxxy[0][0];
	odm_set_bb_reg(dm, 0xc14, 0x3FF, reg);
	reg = iqk->rxxy[0][1] & 0x3F;
	odm_set_bb_reg(dm, 0xc14, 0xFC00, reg);
	reg = (iqk->rxxy[0][1] >> 6) & 0xF;
	odm_set_bb_reg(dm, 0xca0, 0xF0000000, reg);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0xc14 = 0x%x\n",
	       odm_get_bb_reg(dm, 0xc14, MASKDWORD));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0xc4c = 0x%x\n",
	       odm_get_bb_reg(dm, 0xca0, MASKDWORD));
}

void
_iqk_udpate_iqc_8710c(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	if(iqk->iqk_fail_report[0][0][0] != true)
		_iqk_update_txiqc_8710c(dm);
	if(iqk->iqk_fail_report[0][0][1] != true)
		_iqk_update_rxiqc_8710c(dm);	
}

void _iqk_iqk_by_path_8710c(void *dm_void, boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true;
	u8 i, kcount_limit;

	switch (iqk->iqk_step) {
	case 1: /*S0 LOK*/
		_iqk_lok_by_pad_8710c(dm);
#if 0
		_iqk_lok_setting_8710c(dm);
		KFAIL = _iqk_one_shot_8710c(dm, TXIQK);
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_A][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_A][TXIQK]++;
		else
#endif
			
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_A, 0x1);
		break;
	case 2: /*S0 TXIQK*/
#if 1
		_iqk_txk_setting_8710c(dm);
		KFAIL = _iqk_one_shot_8710c(dm, TXIQK);
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_A][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_A][TXIQK]++;
		else
#endif
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_A, 0x1);
		break;
	case 3: /*S0 RXIQK*/
#if 1
		_iqk_rxiqk_8710c(dm);
#else
	iqk->iqk_step++;
#endif
		break;
	case 4: /*update IQC*/
#if 1
		_iqk_udpate_iqc_8710c(dm);
		iqk->iqk_step++;
#else
	iqk->iqk_step++;
#endif
		break;
	}

	if (iqk->iqk_step == IQK_STEP_8710C)
		_iqk_summy_report_8710c(dm);
}

void _iqk_start_iqk_8710c(struct dm_struct *dm, boolean segment_iqk)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i = 0;
	u8 kcount_limit;
#if 0
	/*GNT_WL = 1*/
	tmp = odm_get_rf_reg(dm, RF_PATH_A, RF_0x1, MASK20BITS);
	tmp = tmp | BIT(5) | BIT(0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x1, MASK20BITS, tmp);

	tmp = odm_get_rf_reg(dm, RF_PATH_B, RF_0x1, MASK20BITS);
	tmp = tmp | BIT(5) | BIT(0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x1, MASK20BITS, tmp);
#endif

	while (i <  100) {
		i++;
		_iqk_iqk_by_path_8710c(dm, segment_iqk);
		if (iqk_info->iqk_step == IQK_STEP_8710C)
			break;
		if (segment_iqk && iqk_info->kcount == kcount_limit)
			break;
	}
}

void _iq_calibrate_8710c_init(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k, m;
	static boolean firstrun = true;

	if (firstrun) {
		firstrun = false;
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]=====>PHY_IQCalibrate_8710C_Init\n");

		for (i = 0; i < SS_8710C; i++) {
			for (j = 0; j < 2; j++) {
				iqk->lok_fail[i] = true;
				iqk->iqk_fail[j][i] = true;
				iqk->iqc_matrix[j][i] = 0x40000100;
			}
		}

		for (i = 0; i < 2; i++) {
			iqk->iqk_channel[i] = 0x0;

			for (j = 0; j < SS_8710C; j++) {
				iqk->lok_idac[i][j] = 0x0;
				iqk->rxiqk_agc[i][j] = 0x0;
				iqk->bypass_iqk[i][j] = 0x0;

				for (k = 0; k < 2; k++) {
					iqk->iqk_fail_report[i][j][k] = true;
					for (m = 0; m < 8; m++) {
						iqk->iqk_cfir_real[i][j][k][m]
							= 0x0;
						iqk->iqk_cfir_imag[i][j][k][m]
							= 0x0;
					}
				}

				for (k = 0; k < 3; k++)
					iqk->retry_count[i][j][k] = 0x0;
			}
		}
	}
}

void _phy_iq_calibrate_8710c(struct dm_struct *dm, boolean reset,
			     boolean segment_iqk)
{
	u32 mac_bp[MAC_NUM_8710C], bb_bp[BB_NUM_8710C];
	u32 rf_bp[RF_NUM_8710C][SS_8710C];
	u32 bp_mac_reg[MAC_NUM_8710C] = {0x520};
	u32 bp_bb_reg[BB_NUM_8710C] = {0x874, 0x88c, 0xc04, 0xc08, 0xc50};
	u32 bp_rf_reg[RF_NUM_8710C] = {0xdf, 0xef};
	u32 i = 0;
	boolean is_mp = false;

	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (*dm->mp_mode)
		is_mp = true;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]==IQK strat!!===\n");
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]band_type=%s band_width=%d ExtPA2G=%d ext_pa_5g=%d\n",
	       (*dm->band_type == ODM_BAND_5G) ? "5G" : "2G", *dm->band_width,
	       dm->ext_pa, dm->ext_pa_5g);
	iqk->iqk_times++;
	iqk->kcount = 0;
	iqk->iqk_step = 1;
	iqk->rxiqk_step = 2;
	_iqk_backup_iqk_8710c(dm, 0x0);
	_iqk_bp_macbb_8710c(dm, mac_bp, bb_bp, bp_mac_reg, bp_bb_reg);
	_iqk_bp_rf_8710c(dm, rf_bp, bp_rf_reg);
	while (i < 100) {
		i++;
		_iqk_set_macbb_8710c(dm);
		_iqk_set_afe_8710c(dm, true);
		_iqk_set_rfe_8710c(dm, false);
		_iqk_start_iqk_8710c(dm, segment_iqk);
		_iqk_set_afe_8710c(dm, false);
		_iqk_reload_macbb_8710c(dm, mac_bp, bb_bp, bp_mac_reg,
					bp_bb_reg);
		_iqk_reload_rf_8710c(dm, bp_rf_reg, rf_bp);
		if (iqk->iqk_step == IQK_STEP_8710C)
			break;
		iqk->kcount = 0;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]delay 50ms!!\n");
		ODM_delay_ms(50);
	};
	RF_DBG(dm, DBG_RF_IQK, "[IQK]===IQK end!!===\n");
}

void _phy_iq_calibrate_by_fw_8710c(void *dm_void, u8 clear, u8 segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	enum hal_status status = HAL_STATUS_FAILURE;

	if (*dm->mp_mode)
		clear = 0x1;

	iqk->iqk_times++;
	status = odm_iq_calibrate_by_fw(dm, clear, segment_iqk);

	if (status == HAL_STATUS_SUCCESS)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK OK!!!\n");
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK fail!!!\n");
}

void phy_iq_calibrate_8710c(void *dm_void, boolean clear, boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	/*FW IQK*/
//	if (dm->fw_offload_ability & PHYDM_RF_IQK_OFFLOAD) {
	if (0) {
		_phy_iq_calibrate_by_fw_8710c(dm, clear, (u8)(segment_iqk));
//		phydm_get_read_counter_8710c(dm);
//		halrf_iqk_check_if_reload(dm);
	} else {
		_iq_calibrate_8710c_init(dm);
		_phy_iq_calibrate_8710c(dm, clear, segment_iqk);
	}
	_iqk_fail_count_8710c(dm);
//	halrf_iqk_dbg(dm);
}
#endif
#endif
