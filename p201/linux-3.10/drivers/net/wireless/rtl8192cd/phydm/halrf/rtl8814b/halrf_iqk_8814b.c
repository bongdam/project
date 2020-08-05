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

#if (RTL8814B_SUPPORT == 1)

/*@---------------------------Define Local Constant---------------------------*/
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void do_iqk_8814b(void *dm_void, u8 delta_thermal_index, u8 thermal_value,
		  u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	dm->rf_calibrate_info.thermal_value_iqk = thermal_value;
	halrf_segment_iqk_trigger(dm, true, iqk->segment_iqk);
}
#else
/*Originally config->do_iqk is hooked phy_iq_calibrate_8814b*/
/*But do_iqk_8814b and phy_iq_calibrate_8814b have different arguments*/
void do_iqk_8814b(void *dm_void, u8 delta_thermal_index, u8 thermal_value,
		  u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean is_recovery = (boolean)delta_thermal_index;

	halrf_segment_iqk_trigger(dm, true, iqk->segment_iqk);
}
#endif

#if 0
void _iqk_get_txcfir_8814b(void *dm_void, u8 path, u8 t)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	u8 i;
	u32 tmp;
	u32 bit_mask_20_16 = BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16);


	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);

	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);		

	odm_set_bb_reg(dm, R_0x1bd4, BIT(21), 0x1);
	odm_set_bb_reg(dm, R_0x1bd4, bit_mask_20_16, 0x10);
	for (i = 0; i <= 23; i++) {
		odm_set_bb_reg(dm, R_0x1bd8, MASKDWORD, 0xe0000001 | i << 2);
		tmp = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
		iqk_info->rx_cfir_real[t][path][i] = (tmp & 0x0fff0000) >> 16;
		iqk_info->rx_cfir_imag[t][path][i] = tmp & 0x0fff;		
	}
	for (i = 0; i <= 23; i++)
		RF_DBG(dm, DBG_RF_IQK, "[CC](7) tx_cfir_real[%d][%d][%x] = %2x\n", t, path, i, iqk_info->rx_cfir_real[t][path][i]);		
	for (i = 0; i <= 23; i++)
		RF_DBG(dm, DBG_RF_IQK, "[CC](7) tx_cfir_imag[%d][%d][%x] = %2x\n", t, path, i, iqk_info->rx_cfir_imag[t][path][i]); 
	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
}
#endif

void phy_get_iqk_cfir_8814b(void *dm_void, u8 idx, u8 path, boolean debug)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	u8 i, ch;
	u32 tmp;
	u32 bit_mask_20_16 = BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16);

	if (debug)
		ch = 2;
	else
		ch = 0;

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);

	if (idx == TX_IQK) {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
	} else {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);		
	}
	odm_set_bb_reg(dm, R_0x1bd4, BIT(21), 0x1);
	odm_set_bb_reg(dm, R_0x1bd4, bit_mask_20_16, 0x10);
	for (i = 0; i <= 16; i++) {
		odm_set_bb_reg(dm, R_0x1bd8, MASKDWORD, 0xe0000001 | i << 2);
		tmp = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
		iqk_info->iqk_cfir_real[ch][path][idx][i] =
						(u16)((tmp & 0x0fff0000) >> 16);
		iqk_info->iqk_cfir_imag[ch][path][idx][i] = (u16)(tmp & 0x0fff);		
	}
#if 0
	for (i = 0; i <= 16; i++)
		RF_DBG(dm, DBG_RF_IQK, "[IQK](7) cfir_real[0][%d][%d][%x] = %2x\n", path, idx, i, iqk_info->iqk_cfir_real[0][path][idx][i]);		
	for (i = 0; i <= 16; i++)
		RF_DBG(dm, DBG_RF_IQK, "[IQK](7) cfir_imag[0][%d][%d][%x] = %2x\n", path, idx, i, iqk_info->iqk_cfir_imag[0][path][idx][i]); 
#endif
	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
}

void phy_iqk_show_cfir_8814b(void *dm_void, u8 path, u8 idx)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i;

	for (i = 0; i <= 18; i++) {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]path %-2d %-3s CFIR_real: %-2d: 0x%x\n",
		       path,
		       (idx == 0) ? "TX" : "RX",
		       i,
		       iqk_info->iqk_cfir_real[2][path][idx][i]);
	}
	for (i = 0; i <= 18; i++) {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]path %-2d %-3s CFIR_img:%-2d: 0x%x\n",
		       path,
		       (idx == 0) ? "TX" : "RX",
		       i,
		       iqk_info->iqk_cfir_imag[2][path][idx][i]);
	}
}

void phy_iqk_dbg_cfir_backup_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 path, idx, i;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]%-20s\n", "backup TX/RX CFIR");
	for (path = 0; path < SS_8814B; path++)
		for (idx = 0; idx < 2; idx++)
			phydm_get_iqk_cfir(dm, idx, path, true);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]%-20s\n", "show TX/RX CFIR");		
	for (path = 0; path < SS_8814B; path++)
		for (idx = 0; idx < 2; idx++) {
			RF_DBG(dm, DBG_RF_IQK, "[IQK]path %-2d %-3s",
	       		       path,
	       		       (idx == 0) ? "TX" : "RX");
			phy_iqk_show_cfir_8814b(dm, path, idx);
		}
}

void _iqk_txcfir_rate_en_8814b(struct dm_struct *dm)
{
#if 0
	odm_write_4byte(dm, 0xa74, 0xffffffff);
	odm_write_4byte(dm, 0xa78, 0xffffffff);
	odm_set_bb_reg(dm, 0xa7c, 0xfffff, 0xfffff);
#endif
	odm_write_4byte(dm, 0xa74, 0x0e0e0000);
	odm_write_4byte(dm, 0xa78, 0xf83e0e0e);
	odm_set_bb_reg(dm, 0xa7c, 0xfffff, 0xf83e0);
}

void _iqk_clean_cfir_8814b(struct dm_struct *dm, u8 mode, u8 path)
{
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
	if (mode == TXIQK) {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
		odm_write_4byte(dm, 0x1bd8, 0xc0000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	} else {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);
		odm_write_4byte(dm, 0x1bd8, 0x60000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	}

	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
	odm_write_4byte(dm, 0x1bd8, 0x0);
}

void _iqk_cal_path_off_8814b(struct dm_struct *dm)
{
	u8 path;

	for (path = 0; path < 4; path++) {
		odm_set_rf_reg(dm, (enum rf_path)path, 0x0, 0xfffff, 0x10000);
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD,
			       IQK_CMD_8814B | path << 1);
		odm_write_1byte(dm, 0x1bcc, 0x3f);
	}
}

void _iqk_rf_set_check_8814b(struct dm_struct *dm, u8 path, u16 add, u32 data)
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

void _iqk_fill_iqk_report_8814b(void *dm_void, u8 ch)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 tmp1 = 0x0, tmp2 = 0x0, tmp3 = 0x0, data;
	u8 i;

	for (i = 0; i < SS_8814B; i++) {
		tmp1 += ((iqk->iqk_fail_report[ch][i][TX_IQK] & 1) << i);
		tmp2 += ((iqk->iqk_fail_report[ch][i][RX_IQK] & 1) << (i + 4));
		tmp3 += ((iqk->rxiqk_fail_code[ch][i] & 0x3) << (i * 2 + 8));
	}
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | 0x3 << 1);
	odm_set_bb_reg(dm, R_0x1bf0, 0x0000ffff, tmp1 | tmp2 | tmp3);
	data = iqk->rxiqk_agc[ch][RF_PATH_B] << 16 |
			iqk->rxiqk_agc[ch][RF_PATH_A];
	odm_write_4byte(dm, 0x1bc4, data);
	data = iqk->rxiqk_agc[ch][RF_PATH_D] << 16 |
			iqk->rxiqk_agc[ch][RF_PATH_C];
	odm_write_4byte(dm, 0x1be0, data);
}

void _iqk_fail_count_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;

	dm->n_iqk_cnt++;
	if (odm_get_bb_reg(dm, RF_0x1bf0, BIT(16)) == 1)
		iqk->is_reload = true;
	else
		iqk->is_reload = false;

	if (!iqk->is_reload) {
		for (i = 0; i < 8; i++) {
			if (odm_get_bb_reg(dm, R_0x1bf0, BIT(i)) == 1)
				dm->n_iqk_fail_cnt++;
		}
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]All/Fail = %d %d\n", dm->n_iqk_cnt,
	       dm->n_iqk_fail_cnt);
}

void _iqk_iqk_fail_report_8814b(struct dm_struct *dm)
{
#if 1
	u32 tmp1bf0 = 0x0;
	u8 i;

	tmp1bf0 = odm_read_4byte(dm, 0x1bf0);

	for (i = 0; i < 4; i++) {
		if (tmp1bf0 & (0x1 << i))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d TXIQK\n",
			       i);
#else
			panic_printk("[IQK] please check S%d TXIQK\n", i);
#endif
		if (tmp1bf0 & (0x1 << (i + 12)))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d RXIQK\n",
			       i);
#else
			panic_printk("[IQK] please check S%d RXIQK\n", i);
#endif
	}
#endif
}

void _iqk_bp_macbb_8814b(struct dm_struct *dm, u32 *mac_bp,
			 u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	for (i = 0; i < MAC_NUM_8814B; i++)
		mac_bp[i] = odm_read_4byte(dm, bp_mac_reg[i]);

	for (i = 0; i < BB_NUM_8814B; i++)
		bb_bp[i] = odm_read_4byte(dm, bp_bb_reg[i]);
}

void _iqk_bp_rf_8814b(struct dm_struct *dm, u32 rf_bp[][SS_8814B],
		      u32 *bp_reg)
{
	u8 i, s;

	for (s = 0; s < SS_8814B; s++) {
		for (i = 0; i < RF_NUM_8814B; i++) {
			rf_bp[i][s] = odm_get_rf_reg(dm, (enum rf_path)s,
						     bp_reg[i], MASK20BITS);
		}
	}
}

void _iqk_set_afe_8814b(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, 0x1830, BIT(30), 0x0);
	odm_set_bb_reg(dm, 0x1860, 0xfffff000, 0xf0001);
	odm_set_bb_reg(dm, 0x4130, BIT(30), 0x0);
	odm_set_bb_reg(dm, 0x4160, 0xfffff000, 0xf0001);
	odm_set_bb_reg(dm, 0x5230, BIT(30), 0x0);
	odm_set_bb_reg(dm, 0x5260, 0xfffff000, 0xf0001);
	odm_set_bb_reg(dm, 0x5330, BIT(30), 0x0);
	odm_set_bb_reg(dm, 0x5360, 0xfffff000, 0xf0001);
	/*ADDA FIFO reset*/
	odm_write_4byte(dm, 0x1c38, 0x0);
	ODM_delay_us(10);
	odm_write_4byte(dm, 0x1c38, 0xffffffff);
}

void _iqk_reload_macbb_8814b(struct dm_struct *dm, u32 *mac_bp,
			     u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	/*toggle IGI*/
	odm_write_4byte(dm, 0x1d70, 0x50505050);

	for (i = 0; i < MAC_NUM_8814B; i++)
		odm_write_4byte(dm, bp_mac_reg[i], mac_bp[i]);
	for (i = 0; i < BB_NUM_8814B; i++)
		odm_write_4byte(dm, bp_bb_reg[i], bb_bp[i]);

	/*rx go throughput IQK*/
	odm_set_bb_reg(dm, 0x180c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x410c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x520c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x530c, BIT(31), 0x1);
}

void _iqk_reload_rf_8814b(struct dm_struct *dm, u32 *reg,
			   u32 data[][SS_8814B])
{
	u32 i;

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, MASK20BITS, 0x0);

	for (i = 0; i < RF_NUM_8814B; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, reg[i], 0xfffff, data[i][0]);
		odm_set_rf_reg(dm, RF_PATH_B, reg[i], 0xfffff, data[i][1]);
		odm_set_rf_reg(dm, RF_PATH_C, reg[i], 0xfffff, data[i][2]);
		odm_set_rf_reg(dm, RF_PATH_D, reg[i], 0xfffff, data[i][3]);
	}
}

void _iqk_backup_iqk_8814b_subfunction(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k;

	iqk->iqk_channel[1] = iqk->iqk_channel[0];
	for (i = 0; i < 2; i++) {
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

void _iqk_backup_iqk_8814b(struct dm_struct *dm, u8 step, u8 path)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j;

	switch (step) {
	case 0:
		_iqk_backup_iqk_8814b_subfunction(dm);
		for (i = 0; i < 4; i++) {
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
		iqk->lok_idac[0][path] = odm_get_rf_reg(dm, (enum rf_path)path,
							RF_0x58, MASK20BITS);
		break;
	case 2: /*TXIQK backup*/
	case 3: /*RXIQK backup*/
		phydm_get_iqk_cfir(dm, (step - 2), path, false);
		break;
	}
}

void _iqk_reload_iqk_setting_8814b(struct dm_struct *dm, u8 ch,
				   u8 reload_idx
				   /*1: reload TX, 2: reload LO, TX, RX*/)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, path, idx;
	u16 iqk_apply[2] = {0xc94, 0xe94};
	u32 tmp, data;
	u32 bmask13_12 = (BIT(13) | BIT(12));
	u32 bmask20_16 = (BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16));
	boolean report;

	for (path = 0; path < 2; path++) {
		if (reload_idx == 2) {
			tmp = odm_get_rf_reg(dm, (enum rf_path)path,
					     RF_0xdf, MASK20BITS) | BIT(4);
			_iqk_rf_set_check_8814b(dm, (enum rf_path)path,
						0xdf, tmp);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x58,
				       MASK20BITS, iqk->lok_idac[ch][path]);
		}

		for (idx = 0; idx < reload_idx; idx++) {
			odm_set_bb_reg(dm, R_0x1b00, MASKDWORD,
				       IQK_CMD_8814B | path << 1);
			odm_set_bb_reg(dm, R_0x1b2c, MASKDWORD, 0x7);
//			odm_set_bb_reg(dm, R_0x1b38, MASKDWORD, DIQC);
			odm_set_bb_reg(dm, R_0x1b3c, MASKDWORD, DIQC);
			odm_set_bb_reg(dm, R_0x1bcc, MASKDWORD, 0x00000000);
			if (idx == 0)
				odm_set_bb_reg(dm, R_0x1b0c, bmask13_12, 0x3);
			else
				odm_set_bb_reg(dm, R_0x1b0c, bmask13_12, 0x1);
			odm_set_bb_reg(dm, R_0x1bd4, bmask20_16, 0x10);
			for (i = 0; i < 8; i++) {
				data = ((0xc0000000 >> idx) + 0x3) + (i * 4) +
					(iqk->iqk_cfir_real[ch][path][idx][i]
					<< 9);
				odm_write_4byte(dm, 0x1bd8, data);
				data = ((0xc0000000 >> idx) + 0x1) + (i * 4) +
					(iqk->iqk_cfir_imag[ch][path][idx][i]
					<< 9);
				odm_write_4byte(dm, 0x1bd8, data);
			}
			if (idx == 0) {
				report = !(iqk->iqk_fail_report[ch][path][idx]);
				odm_set_bb_reg(dm, iqk_apply[path],
					       BIT(0), report);
			} else {
				report = !(iqk->iqk_fail_report[ch][path][idx]);
				odm_set_bb_reg(dm, iqk_apply[path],
					       BIT(10), report);
			}
		}
		odm_set_bb_reg(dm, R_0x1bd8, MASKDWORD, 0x0);
		odm_set_bb_reg(dm, R_0x1b0c, bmask13_12, 0x0);
	}
}

boolean
_iqk_reload_iqk_8814b(struct dm_struct *dm, boolean reset)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;

	iqk->is_reload = false;

	if (reset) {
		for (i = 0; i < 2; i++)
			iqk->iqk_channel[i] = 0x0;
	} else {
		iqk->rf_reg18 = odm_get_rf_reg(dm, RF_PATH_A,
					       RF_0x18, MASK20BITS);

		for (i = 0; i < 2; i++) {
			if (iqk->rf_reg18 == iqk->iqk_channel[i]) {
				_iqk_reload_iqk_setting_8814b(dm, i, 2);
				_iqk_fill_iqk_report_8814b(dm, i);
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK]reload IQK result before!!!!\n");
				iqk->is_reload = true;
			}
		}
	}
	/*report*/
	odm_set_bb_reg(dm, R_0x1bf0, BIT(16), (u8)iqk->is_reload);
	return iqk->is_reload;
}

void _iqk_set_rfe_8814b(struct dm_struct *dm)
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



void _iqk_set_macbb_8814b(struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, REG_TXPAUSE, 0xff);
	/*tx go throughput IQK*/
	odm_set_bb_reg(dm, 0x1e24, BIT(17), 0x1);
	/*enable IQK block*/
	odm_set_bb_reg(dm, 0x1cd0, 0xf0000000, 0x7);
	/*Turn off CCA*/
	/*odm_set_bb_reg(dm, 0x1c68, 0x0f000000, 0xf);*/
	odm_set_bb_reg(dm, 0x1d58, 0xff8, 0x1ff);
	/*Release gated clk*/
	odm_set_bb_reg(dm, 0x1834, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x4134, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5234, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5334, BIT(15), 0x1);
	/*dont_rst_sync_path_when_txon*/
	odm_set_bb_reg(dm, 0x1d60, BIT(31), 0x1);
	//Prevent anapar state unknown at sine PSD
	/*OFDM/CCK off*/
	/*odm_set_bb_reg(dm, 0x1c3c, BIT(0), 0x0);*/
	/*odm_set_bb_reg(dm, 0x1c3c, BIT(1), 0x0);*/
	odm_set_bb_reg(dm, 0x1a14, 0x300, 0x3);
	/*prevent CCK CCA*/
	odm_set_bb_reg(dm, 0x1a00, 0x3, 0x2);
	/*rx path on*/
	odm_set_bb_reg(dm, 0x824, 0xf0000, 0xf);
	/*tx_scale_0dB*/
	odm_set_bb_reg(dm, 0x186c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x416c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x526c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x536c, BIT(7), 0x0);
	/*3-wire off*/
	odm_set_bb_reg(dm, 0x180c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x410c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x520c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x530c, 0x3, 0x0);
	/*CIP power on*/
	odm_set_bb_reg(dm, R_0x1b08, BIT(7), 0x1);
}

void _iqk_lok_setting_8814b(struct dm_struct *dm, u8 path)
{
	_iqk_cal_path_off_8814b(dm);
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_1byte(dm, 0x1b2c, 0x08);
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_write_1byte(dm, 0x1b2b, 0x00);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0x57, BIT(19), 0);
		/*@for loop gain*/
		odm_write_4byte(dm, 0x1b20, 0x030401e8);
		odm_write_1byte(dm, 0x1bcc, 0x9);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0xaeee2);
		/*@LOK LUT*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
		break;
	case ODM_BAND_5G:
		odm_write_1byte(dm, 0x1b2b, 0x80);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0x57, BIT(19), 0);
		/*@for loop gain*/
		odm_write_4byte(dm, 0x1b20, 0x030401e8);
		odm_write_1byte(dm, 0x1bcc, 0x9);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0xa8ee8);
		/*@LOK LUT*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
		break;
	}
}

void _iqk_txk_setting_8814b(struct dm_struct *dm, u8 path)
{

	_iqk_cal_path_off_8814b(dm);
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x15);
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_write_1byte(dm, 0x1b2b, 0x00);
		/*@for loop gain*/
		odm_write_4byte(dm, 0x1b20, 0x030401e8);
		odm_write_1byte(dm, 0x1bcc, 0x9);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0xaeee8);
		/*@LOK LUT*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);
		break;
	case ODM_BAND_5G:
		odm_write_1byte(dm, 0x1b2b, 0x80);
		/*@for loop gain*/
		odm_write_4byte(dm, 0x1b20, 0x030401e8);
		odm_write_1byte(dm, 0x1bcc, 0x09);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0xa8ee8);
		/*@LOK LUT*/
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);
		break;
	}
}

void _iqk_rxk1_setting_8814b(struct dm_struct *dm, u8 path)
{
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);

	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_write_1byte(dm, 0x1bcc, 0x9);
		odm_write_1byte(dm, 0x1b2b, 0x00);
		odm_write_4byte(dm, 0x1b20, 0x01450008);
		odm_write_4byte(dm, 0x1b24, 0x01460c88);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0x510e0);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x8f, MASK20BITS, 0xacc00);
		break;
	case ODM_BAND_5G:
		odm_write_1byte(dm, 0x1bcc, 0x09);
		odm_write_1byte(dm, 0x1b2b, 0x80);
		odm_write_4byte(dm, 0x1b20, 0x00850008);
		odm_write_4byte(dm, 0x1b24, 0x00460048);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0x510e0);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x8f, MASK20BITS, 0xadc00);
		break;
	}
}

void _iqk_rxk2_setting_8814b(struct dm_struct *dm, u8 path, boolean is_gs)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	_iqk_cal_path_off_8814b(dm);
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x15);

	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		if (is_gs) {
			iqk->tmp1bcc = 0x9;
			iqk->txgain56 = 0xaa6e8;
		}
		odm_write_1byte(dm, 0x1bcc, iqk->tmp1bcc);
		odm_write_4byte(dm, 0x1b24, 0x00070848);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, iqk->txgain56);
		break;
	case ODM_BAND_5G:
		if (is_gs) {
			iqk->tmp1bcc = 0x09;
			iqk->lna_idx = 0x1;
		}
		odm_write_1byte(dm, 0x1bcc, iqk->tmp1bcc);
		odm_write_4byte(dm, 0x1b24, 0x00070048 | iqk->lna_idx << 10);
//		odm_write_4byte(dm, 0x1b24, 0x00070448);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       0xde, MASK20BITS, 0x90004);
		odm_set_rf_reg(dm, (enum rf_path)path,
			       RF_0x56, MASK20BITS, 0xa8248);
		break;
	}
}


boolean
_iqk_check_cal_8814b(struct dm_struct *dm, u8 path, u8 cmd)
{
	boolean notready = true, fail = true;
	u32 delay_count = 0x0;

	while (notready) {
		if (odm_read_1byte(dm, 0x2d9c) == 0x55) {
			if (cmd == 0x0) /*LOK*/
				fail = false;
			else
				fail = (boolean)
				       odm_get_bb_reg(dm, R_0x1b08, BIT(26));
			notready = false;
		} else {
			ODM_delay_us(10);
			delay_count++;
		}

		if (delay_count >= 20000) {
			fail = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]IQK timeout!!!\n");
			break;
		}
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = 0x%x!!!\n", delay_count);
	return fail;
}

boolean
_iqk_rxk_gsearch_fail_8814b(struct dm_struct *dm, u8 path, u8 step)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD = 0x0, rf_reg0, tmp, bb_idx;
	u8 IQMUX[4] = {0x9, 0x12, 0x1b, 0x24};
	u32 txgain[3] = {0xaaee8, 0xaa6e8, 0xa8ee8};
	u8 idx1, idx2 = 0;

	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]============ S%d RXIQK GainSearch ============\n",
	       path);
	if (step == RXIQK1) {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d RXIQK GainSearch ============\n",
		       path);
		IQK_CMD = 0x208 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
		       step, IQK_CMD);
		odm_write_1byte(dm, 0x1b10, 0x0);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_us(10);
		fail = _iqk_check_cal_8814b(dm, path, 0x1);
	} else if (step == RXIQK2) {
		for (idx1 = 0; idx1 < 4; idx1++) {
			if (iqk->tmp1bcc == IQMUX[idx1])
				break;
		}
		if (idx1 == 4) {
			RF_DBG(dm, DBG_RF_IQK, "[IQK] rx_gs overflow\n");
			return fail;
		}
		if (*dm->band_type == ODM_BAND_2_4G) {
			for (idx2 = 0; idx2 < 3; idx2++) {
				if (iqk->txgain56 == txgain[idx2])
					break;
			}
			if (idx2 == 3) {
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK] rx_gs overflow\n");
				return fail;
			}
		}
		odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
		odm_write_4byte(dm, 0x1bcc, iqk->tmp1bcc);

		IQK_CMD = 0x208 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
		       step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_us(10);
		fail = _iqk_check_cal_8814b(dm, path, 0x1);

		rf_reg0 = odm_get_rf_reg(dm, (enum rf_path)path,
					 RF_0x0, MASK20BITS);
		odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]S%d RF0x0=0x%x tmp1bcc=0x%x RF0x56=0x%x\n",
		       path, rf_reg0, iqk->tmp1bcc, odm_get_rf_reg(dm,
		       (enum rf_path)path, RF_0x56, MASK20BITS));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1b3c = 0x%x\n",
		       odm_read_4byte(dm, 0x1b3c));
		tmp = (rf_reg0 & 0x1fe0) >> 5;
		iqk->lna_idx = tmp >> 5;
		bb_idx = tmp & 0x1f;

		if (*dm->band_type == ODM_BAND_5G) {
		if (bb_idx == 0x1) {
				 if (idx1 != 3)
					idx1++;
			else
				iqk->isbnd = true;
			fail = true;
			} else if (bb_idx >= 0xa) {
				if (iqk->lna_idx < 0x3)
				iqk->lna_idx++;
			else
				iqk->isbnd = true;
			fail = true;
		} else {
			fail = false;
		}
			idx2 = 0x0;
		} else {
			if (bb_idx == 0x1) {
				 if (idx1 != 3)
				 	idx1++;
				else if (idx2 != 2)
					idx2++;
				else
					iqk->isbnd = true;
				fail = true;
			} else if (bb_idx >= 0xa) {
				if (idx1 != 0)
					idx1--;
				else if (idx2 != 0)
					idx2--;
				else
					iqk->isbnd = true;
				fail = true;
			} else {
				fail = false;
			}
		}

		if (iqk->isbnd)
			fail = false;

		iqk->tmp1bcc = IQMUX[idx1];
		iqk->txgain56 = txgain[idx2];
		iqk->rxiqk_agc[0][path]= (idx2 <<10) | (idx1 << 8);

		if (fail && (*dm->band_type == ODM_BAND_5G)) {
			odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
			tmp = (odm_read_4byte(dm, 0x1b24) & 0xffffe3ff) |
				(iqk->lna_idx << 10);
			odm_write_4byte(dm, 0x1b24, tmp);
		} else {
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56,
				       MASK20BITS, iqk->txgain56);
		}
	}
	return fail;
}

boolean
_lok_one_shot_8814b(void *dm_void, u8 path, boolean for_rxk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	boolean LOK_notready = false;
	u32 LOK_temp = 0;
	u32 IQK_CMD = 0x0;
	u32 temp;

	if (for_rxk) {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]======S%d LOK for RXK======\n", path);
		IQK_CMD = 0x1008 | (1 << (4 + path)) | (path << 1);
	} else {
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]======S%d LOK======\n", path);
		IQK_CMD = IQK_CMD_8814B | (1 << (4 + path)) | (path << 1);
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]LOK_Trigger = 0x%x\n", IQK_CMD);
	odm_write_1byte(dm, 0x1b10, 0x0);
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 1);
	/*LOK: CMD ID = 0	{0xf8000018, 0xf8000028}*/
	/*LOK: CMD ID = 0	{0xf8000019, 0xf8000029}*/
	ODM_delay_us(10);
	LOK_notready = _iqk_check_cal_8814b(dm, path, 0x0);
//	if (!for_rxk)
//	_iqk_set_lok_lut_8198f(dm, path);
//	if (!LOK_notready)
//		_iqk_backup_iqk_8198f(dm, 0x1, path);
	if (rf->rf_dbg_comp & DBG_RF_IQK) {
		temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
		if (!LOK_notready)
			RF_DBG(dm, DBG_RF_IQK, "[IQK]0x58 = 0x%x\n", temp);
		else
			RF_DBG(dm, DBG_RF_IQK, "[IQK]=>S%d LOK Fail!!!\n",
			       path);
	}
	iqk->lok_fail[path] = LOK_notready;
	return LOK_notready;
}

boolean
_iqk_nbtxk_oneshot_8814b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD = 0x0;

	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]============ S%d NBTXIQK ============\n", path);
	IQK_CMD = IQK_CMD_8814B | 0x1 << 8 | (1 << (path + 4));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]TXK_Trigger = 0x%x\n", IQK_CMD);
	odm_write_1byte(dm, 0x1b10, 0x0);
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
	fail = _iqk_check_cal_8814b(dm, path, 0x1);
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1b00=0x%x, 0x1b08=0x%x\n",
	       odm_read_4byte(dm, 0x1b00),
	       odm_read_4byte(dm, 0x1b08));
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1b38=0x%x\n",
	       odm_read_4byte(dm, 0x1b38));
	return fail;
}

boolean
_iqk_one_shot_8814b(void *dm_void, u8 path, u8 idx)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD = 0x0, tmp;
	u8 bw;

	if (*dm->band_width >= 2)
		bw = 2;
	else
		bw = *dm->band_width;

	if (idx == TXIQK)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d WBTXIQK ============\n", path);
	else if (idx == RXIQK1)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d WBRXIQK STEP1============\n",
		       path);
	else
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d WBRXIQK STEP2============\n",
		       path);

	if (idx == TXIQK) {
#if (TXWBIQK_EN == 1)
		IQK_CMD = IQK_CMD_8814B |
			((bw + 3) << 8) | (1 << (path + 4));
#else
		IQK_CMD = IQK_CMD_8814B | 0x1 << 8 | (1 << (path + 4));
#endif
		RF_DBG(dm, DBG_RF_IQK, "[IQK]TXK_Trigger = 0x%x\n", IQK_CMD);
		/*{0xf8000418, 0xf800042a} ==> 20 WBTXK (CMD = 4)*/
		/*{0xf8000518, 0xf800052a} ==> 40 WBTXK (CMD = 5)*/
		/*{0xf8000618, 0xf800062a} ==> 80 WBTXK (CMD = 6)*/
	} else if (idx == RXIQK1) {
#if (RXWBIQK_EN == 1)
		if (bw == 2)
			IQK_CMD = 0x808 | (1 << (path + 4));
		else
			IQK_CMD = 0x708 | (1 << (path + 4));
#else
		IQK_CMD = IQK_CMD_8814B | 0x1 << 8 | (1 << (path + 4));
#endif
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RXK1_Trigger = 0x%x\n", IQK_CMD);
		/*{0xf8000718, 0xf800072a} ==> 20 WBTXK (CMD = 7)*/
		/*{0xf8000718, 0xf800072a} ==> 40 WBTXK (CMD = 7)*/
		/*{0xf8000818, 0xf800082a} ==> 80 WBTXK (CMD = 8)*/
	} else if (idx == RXIQK2) {
#if (RXWBIQK_EN == 1)
		IQK_CMD = 0x8 |
			((bw + 6) << 8) | (1 << (path + 4));
#else
		IQK_CMD = IQK_CMD_8814B | 0x2 << 8 | (1 << (path + 4));
#endif
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RXK2_Trigger = 0x%x\n", IQK_CMD);
		/*{0xf8000918, 0xf800092a} ==> 20 WBRXK (CMD = 9)*/
		/*{0xf8000a18, 0xf8000a2a} ==> 40 WBRXK (CMD = 10)*/
		/*{0xf8000b18, 0xf8000b2a} ==> 80 WBRXK (CMD = 11)*/
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
	ODM_delay_us(10);
	fail = _iqk_check_cal_8814b(dm, path, 0x1);

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
		RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]S%d=>0x1b00=0x%x, 0x1b08=0x%x\n", path,
		       odm_read_4byte(dm, 0x1b00), odm_read_4byte(dm, 0x1b08));
		if (idx != TXIQK)
			RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]S%d=>RF0x0=0x%x, RF0x56=0x%x, 0x1bcc=0x%x\n", path,
			       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x0,
					      MASK20BITS),
			       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x56,
				      MASK20BITS),
		      odm_read_4byte(dm, 0x1bcc));

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);

//	if (idx == TXIQK) {
//		if (!fail)
//			_iqk_backup_iqk_8814b(dm, 0x2, path);
//	}
	if (idx == RXIQK2) {
		iqk->rxiqk_agc[0][path] = iqk->rxiqk_agc[0][path] |
			(u16)((odm_get_rf_reg(dm, (enum rf_path)path,
			      RF_0x0, MASK20BITS) >> 5) & 0xff);

//		odm_write_4byte(dm, 0x1b38, DIQC);
//		if (!fail)
//			_iqk_backup_iqk_8814b(dm, 0x3, path);
	}
	if (fail) {
		if (idx == TXIQK)
			_iqk_clean_cfir_8814b(dm, TXIQK, path);
		else if (idx == RXIQK2)
			_iqk_clean_cfir_8814b(dm, RXIQK, path);
	}
	if (idx == TXIQK)
		iqk->iqk_fail_report[0][path][TXIQK] = fail;
	else
		iqk->iqk_fail_report[0][path][RXIQK] = fail;
	return fail;
}

boolean
_iqk_rx_iqk_by_path_8814b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true, gonext = false, gs_limit = false;

#if 1
	switch (iqk->rxiqk_step) {
#if 0
	case 0: /*gain search_RXK1*/
		_iqk_rxk1_setting_8814b(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_rxk_gsearch_fail_8814b(dm, path, RXIQK1);
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
	iqk->rxiqk_step++;
		break;
#endif
	case 0: /*gain search_RXK2*/
#if 1
		_iqk_rxk2_setting_8814b(dm, path, true);
		iqk->isbnd = false;
		while (1) {
			KFAIL = _iqk_rxk_gsearch_fail_8814b(dm, path, RXIQK2);
			if (iqk->gs_retry_count[0][path][1] < rxiqk_gs_limit)
				gs_limit = true;
			else
				gs_limit = false;
			if (KFAIL && gs_limit) {
				iqk->gs_retry_count[0][path][1]++;
			} else {
				iqk->rxiqk_step++;
				break;
			}
		}
//		halrf_iqk_xym_read(dm, path, 0x3);
#else
	iqk->rxiqk_step++;
#endif
		break;
#if 0
	case 2: /*RXK1*/
		_iqk_rxk1_setting_8814b(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8814b(dm, path, RXIQK1);
			if (KFAIL && iqk->retry_count[0][path][RXIQK1] < 2) {
				iqk->retry_count[0][path][RXIQK1]++;
			} else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 1;
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
	iqk->rxiqk_step++;
		break;
#endif
	case 1: /*RXK2*/
		_iqk_rxk2_setting_8814b(dm, path, false);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8814b(dm, path, RXIQK2);
			if (KFAIL && iqk->retry_count[0][path][RXIQK2] < 2) {
				iqk->retry_count[0][path][RXIQK2]++;
			} else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 2;
				iqk->rxiqk_step = 2;
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

void _iqk_summy_report_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]===LOK summary ===\n");
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]S0_LOK_fail = %d, S1_LOK_fail = %d,",
	       iqk->lok_fail[RF_PATH_A], iqk->lok_fail[RF_PATH_B]);
	RF_DBG(dm, DBG_RF_IQK,
	       "S2_LOK_fail = %d, S3_LOK_fail = %d\n",
	       iqk->lok_fail[RF_PATH_C], iqk->lok_fail[RF_PATH_D]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]===IQK summary ===\n");

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXK_fail = %d, S1_TXK_fail = %d,",
	       iqk->iqk_fail_report[0][RF_PATH_A][TXIQK],
	       iqk->iqk_fail_report[0][RF_PATH_B][TXIQK]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_TXIQK_fail = %d, S3_TXIQK_fail = %d\n",
	       iqk->iqk_fail_report[0][RF_PATH_C][TXIQK],
	       iqk->iqk_fail_report[0][RF_PATH_D][TXIQK]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK_fail = %d, S1_RXK_fail = %d,",
	       iqk->iqk_fail_report[0][RF_PATH_A][RXIQK],
	       iqk->iqk_fail_report[0][RF_PATH_B][RXIQK]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_RXK_fail = %d, S3_RXK_fail = %d\n",
	       iqk->iqk_fail_report[0][RF_PATH_C][RXIQK],
	       iqk->iqk_fail_report[0][RF_PATH_D][RXIQK]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXK_retry = %d, S1_TXK_retry = %d,\n",
	       iqk->retry_count[0][RF_PATH_A][TXIQK],
	       iqk->retry_count[0][RF_PATH_B][TXIQK]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_TXK_retry = %d, S3_TXK_retry = %d\n",
	       iqk->retry_count[0][RF_PATH_C][TXIQK],
	       iqk->retry_count[0][RF_PATH_D][TXIQK]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK1_retry = %d, S0_RXK2_retry = %d,",
	       iqk->retry_count[0][RF_PATH_A][RXIQK1],
	       iqk->retry_count[0][RF_PATH_A][RXIQK2]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S1_RXK1_retry = %d, S1_RXK2_retry = %d\n",
	       iqk->retry_count[0][RF_PATH_B][RXIQK1],
	       iqk->retry_count[0][RF_PATH_B][RXIQK2]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_RXK1_retry = %d, S2_RXK2_retry = %d,",
	       iqk->retry_count[0][RF_PATH_C][RXIQK1],
	       iqk->retry_count[0][RF_PATH_C][RXIQK2]);
	RF_DBG(dm, DBG_RF_IQK, "S3_RXK1_retry = %d, S3_RXK2_retry = %d\n",
	       iqk->retry_count[0][RF_PATH_D][RXIQK1],
	       iqk->retry_count[0][RF_PATH_D][RXIQK2]);

	RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_GS1_retry = %d, S0_GS2_retry = %d,",
	       iqk->gs_retry_count[0][RF_PATH_A][0],
	       iqk->gs_retry_count[0][RF_PATH_A][1]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S1_GS1_retry = %d, S1_GS2_retry = %d\n",
	       iqk->gs_retry_count[0][RF_PATH_B][0],
	       iqk->gs_retry_count[0][RF_PATH_B][1]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_GS1_retry = %d, S2_GS2_retry = %d,",
	       iqk->gs_retry_count[0][RF_PATH_C][0],
	       iqk->gs_retry_count[0][RF_PATH_C][1]);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S3_GS1_retry = %d, S3_GS2_retry = %d\n",
	       iqk->gs_retry_count[0][RF_PATH_D][0],
	       iqk->gs_retry_count[0][RF_PATH_D][1]);
}

void _iqk_rxiqk(void *dm_void, u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true;
	u8 c = 0;

	while (c < 100) {
		c++;
		KFAIL = _iqk_rx_iqk_by_path_8814b(dm, rf_path);
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]S%dRXK KFail = 0x%x\n", rf_path, KFAIL);
		if (iqk->rxiqk_step == RXK_STEP_8814B) {
			iqk->iqk_step++;
			iqk->rxiqk_step = 0;
			if (KFAIL)
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK]S%dRXK fail code: %d!!!\n",
				       rf_path,
				       iqk->rxiqk_fail_code[0][rf_path]);
			break;
		}
	}
	iqk->kcount++;
}

boolean
_lok_check(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 tmp0x58;
	u8 idac_i, idac_q;
	
	tmp0x58 = odm_get_rf_reg(dm, path, 0x58, RFREG_MASK);
	idac_i = (u8)((tmp0x58 & 0xfc000) >> 14);
	idac_q = (u8)((tmp0x58 & 0x3f00) >> 8);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]idac_i=%d, idac_q=%d\n", idac_i, idac_q);

	if (idac_i > 60 || idac_i < 3 || idac_q > 60 || idac_q < 3)
		return false;
	else
		return true;
}

void _iqk_lok_tune_8814b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 idac_bs = 0x0;

	while (1) {
		odm_set_rf_reg(dm, (enum rf_path)path, 0x57, 0xe00, idac_bs);
		_iqk_lok_setting_8814b(dm, path);
		_lok_one_shot_8814b(dm, path, false);		
		RF_DBG(dm, DBG_RF_IQK, "[IQK]ibs = %d\n", idac_bs);
		if(!_lok_check(dm, path)) {
			if(idac_bs == 0)
				break;
			else
				idac_bs++;
		} else {
			break;
		}
	}
}

void _iqk_iqk_by_path_8814b(void *dm_void, boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true;
	u8 i, kcount_limit;

#if 1
	switch (iqk->iqk_step) {
	case 0: /*S0 LOK*/
#if 1
		_iqk_lok_tune_8814b(dm, RF_PATH_A);
#endif
		iqk->iqk_step++;
		break;
	case 1: /*S0 TXIQK*/
#if 1
		_iqk_txk_setting_8814b(dm, RF_PATH_A);
		KFAIL = _iqk_nbtxk_oneshot_8814b(dm, RF_PATH_A);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0 NBTXK KFail = 0x%x\n", KFAIL);
		if(!KFAIL) {
			_iqk_txk_setting_8814b(dm, RF_PATH_A);
			KFAIL = _iqk_one_shot_8814b(dm, RF_PATH_A, TXIQK);
		}
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0 WBTXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_A][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_A][TXIQK]++;
		else
#endif
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_A, 0x1);
//		_iqk_get_txcfir_8814b(dm,RF_PATH_A, 0);
		break;
	case 2: /*S0 RXIQK*/
#if 1
		if (iqk->iqk_fail_report[0][RF_PATH_A][TXIQK] != true) {
		_iqk_rxiqk(dm, RF_PATH_A);
		} else {
			iqk->iqk_fail_report[0][RF_PATH_A][RXIQK] = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]bypass S0 RXK\n");
			iqk->iqk_step++;
		}
#else
	iqk->iqk_step++;
#endif
//		_iqk_get_txcfir_8814b(dm,RF_PATH_A, 0);
		break;
	case 3: /*S1 LOK*/
#if 1
		_iqk_lok_tune_8814b(dm, RF_PATH_B);
#endif
		iqk->iqk_step++;
		break;
	case 4: /*S1 TXIQK*/
#if 1
		_iqk_txk_setting_8814b(dm, RF_PATH_B);
		KFAIL = _iqk_nbtxk_oneshot_8814b(dm, RF_PATH_B);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S1 NBTXK KFail = 0x%x\n", KFAIL);
		if(!KFAIL) {
			_iqk_txk_setting_8814b(dm, RF_PATH_B);			
			KFAIL = _iqk_one_shot_8814b(dm, RF_PATH_B, TXIQK);
		}
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S1 WBTXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_B][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_B][TXIQK]++;
		else
#endif
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_B, 0x1);
		break;
	case 5: /*S1 RXIQK*/
#if 1
		if (iqk->iqk_fail_report[0][RF_PATH_B][TXIQK] != true) {
		_iqk_rxiqk(dm, RF_PATH_B);
		} else {
			iqk->iqk_fail_report[0][RF_PATH_B][RXIQK] = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]bypass S1 RXK\n");
			iqk->iqk_step++;
		}
#else
	iqk->iqk_step++;
#endif
		break;
	case 6: /*S2 LOK*/
#if 1
		_iqk_lok_tune_8814b(dm, RF_PATH_C);
#endif
		iqk->iqk_step++;
		break;
	case 7: /*S2 TXIQK*/
#if 1
		_iqk_txk_setting_8814b(dm, RF_PATH_C);
		KFAIL = _iqk_nbtxk_oneshot_8814b(dm, RF_PATH_C);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2 NBTXK KFail = 0x%x\n", KFAIL);
		if(!KFAIL) {
			_iqk_txk_setting_8814b(dm, RF_PATH_C);
			KFAIL = _iqk_one_shot_8814b(dm, RF_PATH_C, TXIQK);
		}
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2 WBTXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_C][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_C][TXIQK]++;
		else
#endif
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_C, 0x1);
		break;
	case 8: /*S2 RXIQK*/
#if 1
		if (iqk->iqk_fail_report[0][RF_PATH_C][TXIQK] != true) {
		_iqk_rxiqk(dm, RF_PATH_C);
		} else {
			iqk->iqk_fail_report[0][RF_PATH_C][RXIQK] = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]bypass S2 RXK\n");
			iqk->iqk_step++;
		}
		
#else
	iqk->iqk_step++;
#endif
		break;
	case 9: /*S3 LOK*/
#if 1
		_iqk_lok_tune_8814b(dm, RF_PATH_D);
#endif
		iqk->iqk_step++;
		break;
	case 10: /*S3 TXIQK*/
#if 1
		_iqk_txk_setting_8814b(dm, RF_PATH_D);
		KFAIL = _iqk_nbtxk_oneshot_8814b(dm, RF_PATH_D);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S3 NBTXK KFail = 0x%x\n", KFAIL);
		if(!KFAIL) {
			_iqk_txk_setting_8814b(dm, RF_PATH_D);
			KFAIL = _iqk_one_shot_8814b(dm, RF_PATH_D, TXIQK);
		}
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S3 WBTXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_D][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_D][TXIQK]++;
		else
#endif
			iqk->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_D, 0x1);
		break;
	case 11: /*S3 RXIQK*/
#if 1
		if (iqk->iqk_fail_report[0][RF_PATH_D][TXIQK] != true) {
		_iqk_rxiqk(dm, RF_PATH_D);
		} else {
			iqk->iqk_fail_report[0][RF_PATH_D][RXIQK] = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]bypass S3 RXK\n");
			iqk->iqk_step++;
		}
#else
	iqk->iqk_step++;
#endif
		break;
	}

	if (iqk->iqk_step == IQK_STEP_8814B) {
		_iqk_summy_report_8814b(dm);
		odm_set_bb_reg(dm, R_0x1b08, BIT(7), 0x0);
		for (i = 0; i < SS_8814B; i++) {
			odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | i << 1);
			odm_write_1byte(dm, 0x1bcc, 0x0);
		}
	}
#endif
}

void _iqk_start_iqk_8814b(struct dm_struct *dm, boolean segment_iqk)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 c = 0;
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

	if (*dm->band_width >= 2)
		kcount_limit = kcount_limit_80m;
	else
		kcount_limit = kcount_limit_others;

	while (c <  100) {
		c++;
		_iqk_iqk_by_path_8814b(dm, segment_iqk);
		if (iqk_info->iqk_step == IQK_STEP_8814B)
			break;
		if (segment_iqk && iqk_info->kcount == kcount_limit)
			break;
	}
}

void _iq_calibrate_8814b_init(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k, m;
	static boolean firstrun = true;

	if (firstrun) {
		firstrun = false;
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]=====>PHY_IQCalibrate_8814B_Init\n");

		for (i = 0; i < SS_8814B; i++) {
			for (j = 0; j < 2; j++) {
				iqk->lok_fail[i] = true;
				iqk->iqk_fail[j][i] = true;
				iqk->iqc_matrix[j][i] = DIQC;
			}
		}

		for (i = 0; i < 2; i++) {
			iqk->iqk_channel[i] = 0x0;

			for (j = 0; j < SS_8814B; j++) {
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

boolean
_iqk_rximr_rxk1_test_8814b(struct dm_struct *dm, u8 path, u32 tone_index)
{
	boolean fail = true;
	u32 IQK_CMD, reg_1b20, reg_1b24;

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	reg_1b20 = (odm_read_4byte(dm, 0x1b20) & 0x000fffff);
	odm_write_4byte(dm, 0x1b20, reg_1b20 | ((tone_index & 0xfff) << 20));
	reg_1b24 = (odm_read_4byte(dm, 0x1b24) & 0x000fffff);
	odm_write_4byte(dm, 0x1b24, reg_1b24 | ((tone_index & 0xfff) << 20));

	IQK_CMD = 0x208 | (1 << (path + 4));
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);

	ODM_delay_ms(IQK_DELAY_8814B);
	fail = _iqk_check_cal_8814b(dm, path, 0x1);
	return fail;
}

u32 _iqk_tximr_selfcheck_8814b(void *dm_void, u8 tone_index, u8 path)
{
	u32 tx_ini_power_H[2], tx_ini_power_L[2];
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD;
	u32 tximr = 0x0;
	u8 i;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	/*backup*/
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
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
//	odm_write_4byte(dm, 0x1b38, DIQC);
	odm_write_4byte(dm, 0x1b3c, DIQC);
	/* ======derive pwr1========*/
	for (i = 0; i < 2; i++) {
		odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
		if (i == 0)
			odm_write_4byte(dm, 0x1bcc, 0x0f);
		else
			odm_write_4byte(dm, 0x1bcc, 0x09);
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
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_4byte(dm, 0x1b0c, tmp1);
	odm_write_4byte(dm, 0x1b14, tmp2);
	odm_write_4byte(dm, 0x1b1c, tmp3);
	odm_write_4byte(dm, 0x1b20, tmp4);
	odm_write_4byte(dm, 0x1b24, tmp5);

	if (tx_ini_power_H[1] == tx_ini_power_H[0])
		tximr = (3 * (halrf_psd_log2base(tx_ini_power_L[0] << 2) -
			 halrf_psd_log2base(tx_ini_power_L[1]))) / 100;
	else
		tximr = 0;
	return tximr;
}

void _iqk_start_tximr_test_8814b(struct dm_struct *dm, u8 imr_limit)
{
	boolean KFAIL;
	u8 path, i, tone_index;
	u32 imr_result;

	for (path = 0; path < 2; path++) {
		_iqk_txk_setting_8814b(dm, path);
		KFAIL = _iqk_one_shot_8814b(dm, path, TXIQK);
		for (i = 0x0; i < imr_limit; i++) {
			tone_index = (u8)(0x08 | i << 4);
			imr_result = _iqk_tximr_selfcheck_8814b(dm, tone_index,
								path);
			RF_DBG(dm, DBG_RF_IQK,
			       "[IQK]path=%x, toneindex = %x, TXIMR = %d\n",
			       path, tone_index, imr_result);
		}
		RF_DBG(dm, DBG_RF_IQK, "\n");
	}
}

u32 _iqk_rximr_selfcheck_8814b(void *dm_void, u32 tone_index, u8 path,
			       u32 tmp1b38)
{
	/*[0]: psd tone; [1]: image tone*/
	u32 rx_ini_power_H[2], rx_ini_power_L[2];
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD;
	u8 i, count = 0x0;
	u32 rximr = 0x0;

	struct dm_struct *dm = (struct dm_struct *)dm_void;

	/*backup*/
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
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
	odm_write_4byte(dm, 0x1b3c, DIQC);

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
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 1) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 1;
			break;
		case 2:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 2) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 3:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 2) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 4:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 3) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 5:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 3) | 0xa0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 6:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 3) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 7:
			rx_ini_power_L[0] =
				(u32)((rx_ini_power_L[0] >> 3) | 0xe0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		default:
			break;
		}
	rximr = (u32)(3 * ((halrf_psd_log2base(rx_ini_power_L[0] / 100) -
		      halrf_psd_log2base(rx_ini_power_L[1] / 100))) / 100);
	return rximr;
}

boolean _iqk_get_rxk1_8814b(struct dm_struct *dm, u8 path, u8 imr_limit,
			    u8 side, u32 temp[][15])
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean kfail = true;
	u8 i, count = 0;
	u32 tone_index;

	for (i = 0; i < imr_limit; i++) {
		if (side == 0)
			tone_index = 0xff8 - (i << 4);
		else
			tone_index = 0x08 | (i << 4);
		while (count < 3) {
			_iqk_rxk1_setting_8814b(dm, path);
			kfail = _iqk_rximr_rxk1_test_8814b(dm, path,
							   tone_index);
			RF_DBG(dm,
			       DBG_RF_IQK,
			       "[IQK]path = %x, kfail = %x\n",
			       path, kfail);
			if (kfail) {
				count++;
				if (count == 3) {
					temp[side][i] = DIQC;
					RF_DBG(dm,
					       DBG_RF_IQK,
					       "[IQK]path = %x",
					       path);
					RF_DBG(dm,
					       DBG_RF_IQK,
					       "toneindex = %x rxk1 fail\n",
					       tone_index);
				}
			} else {
				odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |
					path << 1);
				odm_write_4byte(dm, 0x1b1c, 0xa2193c32);
				odm_write_4byte(dm, 0x1b14, 0xe5);
				odm_write_4byte(dm, 0x1b14, 0x0);
				temp[side][i] = odm_read_4byte(dm, 0x1b38);
				RF_DBG(dm,
				       DBG_RF_IQK,
				       "[IQK]path = 0x%x", path);
				RF_DBG(dm,
				       DBG_RF_IQK,
				       "[tone_idx = 0x%x", tone_index);
				RF_DBG(dm,
				       DBG_RF_IQK,
				       "[tmp1b38 = 0x%x\n", temp[side][i]);
				break;
			}
		}
	}
	return kfail;
}

void _iqk_get_rxk2_8814b(struct dm_struct *dm, u8 path, u8 imr_limit, u8 side,
			 u32 temp[][15])
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;
	u32 tone_index, imr_result;
	char *freq[15] = {
		"1.25MHz", "3.75MHz", "6.25MHz", "8.75MHz", "11.25MHz",
		"13.75MHz", "16.25MHz", "18.75MHz", "21.25MHz", "23.75MHz",
		"26.25MHz", "28.75MHz", "31.25MHz", "33.75MHz", "36.25MHz"};

	for (i = 0x0; i < imr_limit; i++) {
		if (side == 0)
			tone_index = 0xff8 - (i << 4);
		else
			tone_index = 0x08 | (i << 4);
		_iqk_rxk2_setting_8814b(dm, path, false);
		imr_result = _iqk_rximr_selfcheck_8814b(dm,
							tone_index,
							path,
							temp[side][i]);
		RF_DBG(dm,
		       DBG_RF_IQK, "[IQK]tone_idx = 0x%5x,", tone_index);
		RF_DBG(dm,
		       DBG_RF_IQK,
		       "freq =%s%10s,",
		       (side == 0) ? "-" : " ",
		       freq[i]);
		RF_DBG(dm,
		       DBG_RF_IQK,
		       "RXIMR = %5d dB\n", imr_result);
	}
}

void _iqk_rximr_test_8814b(struct dm_struct *dm, u8 path, u8 imr_limit)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean kfail;
	u8 i, step, count, side;
	u32 imr_result = 0, tone_index;
	u32 temp = 0, temp1b38[2][15];
	u32 cmd = 0xf8000008;

	for (step = 1; step < 5; step++) {
		count = 0;
		switch (step) {
		case 1: /*gain search_RXK1*/
			_iqk_rxk1_setting_8814b(dm, path);
			while (count < 3) {
				kfail = _iqk_rxk_gsearch_fail_8814b(dm, path,
								    RXIQK1);
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK]path = %x, kfail = %x\n", path,
				       kfail);
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
			_iqk_rxk2_setting_8814b(dm, path, true);
			iqk->isbnd = false;
			while (count < 8) {
				kfail = _iqk_rxk_gsearch_fail_8814b(dm, path,
								    RXIQK2);
				RF_DBG(dm, DBG_RF_IQK,
				       "[IQK]path = %x, kfail = %x\n", path,
				       kfail);
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
			odm_write_4byte(dm, 0x1b00, cmd | path << 1);
			temp = odm_read_4byte(dm, 0x1b1c);
			for (side = 0; side < 2; side++) {
				kfail = _iqk_get_rxk1_8814b(dm,
							    path,
							    imr_limit,
							    side,
							    temp1b38);
				if (kfail) {
					step = 5;
					break;
				}
			}
			break;
		case 4: /*get RX IMR*/
			for (side = 0; side < 2; side++) {
				_iqk_get_rxk2_8814b(dm, path, imr_limit, side,
						    temp1b38);
				odm_write_4byte(dm, 0x1b00, cmd | path << 1);
				odm_write_4byte(dm, 0x1b1c, temp);
//				odm_write_4byte(dm, 0x1b38, DIQC);
			}
			break;
		}
	}
}

void _iqk_start_rximr_test_8814b(struct dm_struct *dm, u8 imr_limit)
{
	u8 path;

	for (path = 0; path < 2; path++)
		_iqk_rximr_test_8814b(dm, path, imr_limit);
}

void _iqk_start_imr_test_8814b(void *dm_void)
{
	u8 imr_limit;

	struct dm_struct *dm = (struct dm_struct *)dm_void;

	if (*dm->band_width == 2)
		imr_limit = 0xf;
	else if (*dm->band_width == 1)
		imr_limit = 0x8;
	else
		imr_limit = 0x4;
#if 0
	/*	_iqk_start_tximr_test_8814b(dm, imr_limit);*/
#endif
	_iqk_start_rximr_test_8814b(dm, imr_limit);
}

void _phy_iq_calibrate_8814b(struct dm_struct *dm, boolean reset,
			     boolean segment_iqk)
{
	u32 mac_bp[MAC_NUM_8814B], bb_bp[BB_NUM_8814B];
	u32 rf_bp[RF_NUM_8814B][SS_8814B];
	u32 bp_mac_reg[MAC_NUM_8814B] = {0x520};
	u32 bp_bb_reg[BB_NUM_8814B] = {0x1c38, 0x1d58, 0x1d60, 0x180c, 0x410c,
				       0x520c, 0x530c, 0x1d70, 0x1a00, 0x824,
				       0x1a14, 0x1830, 0x4130, 0x5230, 0x5330,
				       0x1860, 0x4160, 0x5260, 0x5360, 0x183c,
				       0x1840, 0x1844, 0x413c, 0x4140, 0x4144,
				       0x523c, 0x5240, 0x5244, 0x533c, 0x5340,
				       0x5344};
	u32 bp_rf_reg[RF_NUM_8814B] = {0xde};
	boolean is_mp = false;

	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (*dm->mp_mode)
		is_mp = true;
#if 0
	if (!is_mp)
		if (_iqk_reload_iqk_8814b(dm, reset))
#endif
	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK strat!!!!!==========\n");
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]band_type=%s band_width=%d ExtPA2G=%d ext_pa_5g=%d\n",
	       (*dm->band_type == ODM_BAND_5G) ? "5G" : "2G", *dm->band_width,
	       dm->ext_pa, dm->ext_pa_5g);
	iqk->iqk_times++;
	iqk->kcount = 0;
	iqk->iqk_step = 0;
	iqk->rxiqk_step = 0;
	_iqk_backup_iqk_8814b(dm, 0x0, 0x0);
	_iqk_bp_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg, bp_bb_reg);
	_iqk_bp_rf_8814b(dm, rf_bp, bp_rf_reg);
	while (1) {
		_iqk_set_macbb_8814b(dm);
		_iqk_set_afe_8814b(dm);
		_iqk_set_rfe_8814b(dm);
		_iqk_start_iqk_8814b(dm, segment_iqk);
		_iqk_reload_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg,
					bp_bb_reg);
		_iqk_reload_rf_8814b(dm, bp_rf_reg, rf_bp);
		if (iqk->iqk_step == IQK_STEP_8814B)
			break;
		iqk->kcount = 0;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]delay 50ms!!!\n");
		ODM_delay_ms(50);
	};
	_iqk_txcfir_rate_en_8814b(dm);
	_iqk_fill_iqk_report_8814b(dm, 0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK end!!!!!==========\n");
}

void _phy_iq_calibrate_by_fw_8814b(void *dm_void, u8 clear, u8 segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	enum hal_status status = HAL_STATUS_FAILURE;

	if (*dm->mp_mode)
		clear = 0x1;
#if 0
	/*	else if (dm->is_linked)*/
	/*		segment_iqk = 0x1;*/
#endif

	iqk->iqk_times++;
	status = odm_iq_calibrate_by_fw(dm, clear, segment_iqk);

	if (status == HAL_STATUS_SUCCESS)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK OK!!!\n");
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK fail!!!\n");
}

void phy_iq_calibrate_8814b(void *dm_void, boolean clear, boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, true);
	/*FW IQK*/
//	if (dm->fw_offload_ability & PHYDM_RF_IQK_OFFLOAD) {
	if (0) {
		_phy_iq_calibrate_by_fw_8814b(dm, clear, (u8)(segment_iqk));
//		phydm_get_read_counter_8814b(dm);
//		halrf_iqk_check_if_reload(dm);
	} else {
		_iq_calibrate_8814b_init(dm);
		_phy_iq_calibrate_8814b(dm, clear, segment_iqk);
	}
	_iqk_fail_count_8814b(dm);
	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, false);
#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	_iqk_iqk_fail_report_8814b(dm);
#endif
	halrf_iqk_dbg(dm);
	phydm_bb_reset_8814b(dm);
//	_iqk_get_txcfir_8814b(dm,RF_PATH_A, 0);
}

void _phy_imr_measure_8814b(struct dm_struct *dm)
{
	u32 mac_bp[MAC_NUM_8814B], bb_bp[BB_NUM_8814B];
	u32 rf_bp[RF_NUM_8814B][SS_8814B];
	u32 bp_mac_reg[MAC_NUM_8814B] = {0x520};
	u32 bp_bb_reg[BB_NUM_8814B] = {0x1c38, 0x1c68, 0x1d60, 0x180c, 0x410c,
				       0x520c, 0x530c, 0x1d70, 0x1a00, 0x824,
				       0x1a14};
	u32 bp_rf_reg[RF_NUM_8814B] = {0xde};

	_iqk_backup_iqk_8814b(dm, 0x0, 0x0);
	_iqk_bp_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg, bp_bb_reg);
	_iqk_bp_rf_8814b(dm, rf_bp, bp_rf_reg);
	_iqk_set_macbb_8814b(dm);
	_iqk_set_afe_8814b(dm);
	_iqk_set_rfe_8814b(dm);

	_iqk_start_imr_test_8814b(dm);

	_iqk_set_afe_8814b(dm);
	_iqk_reload_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg, bp_bb_reg);
	_iqk_reload_rf_8814b(dm, bp_rf_reg, rf_bp);
}

void do_imr_test_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]  ************IMR Test *****************\n");
	_phy_imr_measure_8814b(dm);
	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]  **********End IMR Test *******************\n");
}
#endif
