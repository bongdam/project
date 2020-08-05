/******************************************************************************
 *
 * Copyright(c) 2007 - 2017 Realtek Corporation.
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

#if (RTL8710C_SUPPORT == 1)

/*------------------Define Local Constant----------------*/

/*  Tx Power Tracking */
void set_iqk_matrix_8710c(
	struct dm_struct *dm,
	u8 OFDM_index,
	u8 rf_path,
	s32 iqk_result_x,
	s32 iqk_result_y)
{
	s32 ele_A = 0, ele_D = 0, ele_C = 0, value32;
	s32 ele_A_ext = 0, ele_C_ext = 0, ele_D_ext = 0;

	if (OFDM_index >= OFDM_TABLE_SIZE)
		OFDM_index = OFDM_TABLE_SIZE - 1;
	else if (OFDM_index < 0)
		OFDM_index = 0;

	if (iqk_result_x != 0 && (*dm->band_type == ODM_BAND_2_4G)) {
		/* new element D */
		ele_D = (ofdm_swing_table_new[OFDM_index] & 0xFFC00000) >> 22;
		ele_D_ext = (((iqk_result_x * ele_D) >> 7) & 0x01);
		/* new element A */
		if ((iqk_result_x & 0x00000200) != 0) /* consider minus */
			iqk_result_x = iqk_result_x | 0xFFFFFC00;
		ele_A = ((iqk_result_x * ele_D) >> 8) & 0x000003FF;
		ele_A_ext = ((iqk_result_x * ele_D) >> 7) & 0x1;
		/* new element C */
		if ((iqk_result_y & 0x00000200) != 0)
			iqk_result_y = iqk_result_y | 0xFFFFFC00;
		ele_C = ((iqk_result_y * ele_D) >> 8) & 0x000003FF;
		ele_C_ext = ((iqk_result_y * ele_D) >> 7) & 0x1;

		switch (rf_path) {
		case RF_PATH_A:
			/* write new elements A, C, D to regC80, regC94, reg0xc4c, and element B is always 0 */
			/* write 0xc80 */
			value32 = (ele_D << 22) | ((ele_C & 0x3F) << 16) | ele_A;
			odm_set_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE, MASKDWORD, value32);
			/* write 0xc94 */
			value32 = (ele_C & 0x000003C0) >> 6;
			odm_set_bb_reg(dm, REG_OFDM_0_XC_TX_AFE, MASKH4BITS, value32);
			/* write 0xc4c */
			value32 = (ele_D_ext << 28) | (ele_A_ext << 31) | (ele_C_ext << 29);
			value32 = (odm_get_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, MASKDWORD) & (~(BIT(31) | BIT(29) | BIT(28)))) | value32;
			odm_set_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, MASKDWORD, value32);
			break;

		default:
			break;
		}
	}
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "TxPwrTracking path %c: X = 0x%x, Y = 0x%x ele_A = 0x%x ele_C = 0x%x ele_D = 0x%x ele_A_ext = 0x%x ele_C_ext = 0x%x ele_D_ext = 0x%x\n",
	       (rf_path == RF_PATH_A ? 'A' : 'B'), (u32)iqk_result_x,
	       (u32)iqk_result_y, (u32)ele_A, (u32)ele_C, (u32)ele_D,
	       (u32)ele_A_ext, (u32)ele_C_ext, (u32)ele_D_ext);
}

void set_cck_filter_coefficient_8710c(
	struct dm_struct *dm,
	u8 cck_swing_index)
{
	odm_set_bb_reg(dm, R_0xab4, 0x000007FF, cck_swing_table_ch1_ch14_8710c[cck_swing_index]);
}

boolean
get_mix_mode_tx_agc_bbs_wing_offset_8710c(void *dm_void,
					  enum pwrtrack_method method,
					  u8 rf_path,
					  u8 tx_power_index_offest_upper_bound,
					  s8 tx_power_index_offest_lower_bound)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 bb_swing_upper_bound = cali_info->default_ofdm_index + 12;
	u8 bb_swing_lower_bound = 0;

	s8 tx_agc_index = 0;
	u8 tx_bb_swing_index = cali_info->default_ofdm_index;
	u8 tx_cck_bb_swing_index = cali_info->default_cck_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "Path_%d pRF->absolute_ofdm_swing_idx[rf_path]=%d, tx_power_index_offest_upper_bound=%d, tx_power_index_offest_lower_bound=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       tx_power_index_offest_upper_bound,
	       tx_power_index_offest_lower_bound);

	if (tx_power_index_offest_upper_bound > 30)
		tx_power_index_offest_upper_bound = 30;

	if (tx_power_index_offest_lower_bound < -30)
		tx_power_index_offest_lower_bound = -30;

	if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 && cali_info->absolute_ofdm_swing_idx[rf_path] <= tx_power_index_offest_upper_bound) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
		tx_cck_bb_swing_index = cali_info->default_cck_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] > tx_power_index_offest_upper_bound)) {
		tx_agc_index = tx_power_index_offest_upper_bound;
		cali_info->remnant_ofdm_swing_idx[rf_path] = cali_info->absolute_ofdm_swing_idx[rf_path] - tx_power_index_offest_upper_bound;
		tx_bb_swing_index = cali_info->default_ofdm_index + cali_info->remnant_ofdm_swing_idx[rf_path];
		tx_cck_bb_swing_index = cali_info->default_cck_index + cali_info->remnant_ofdm_swing_idx[rf_path];

		if (tx_bb_swing_index > bb_swing_upper_bound) {
			tx_bb_swing_index = bb_swing_upper_bound;
			tx_cck_bb_swing_index = bb_swing_upper_bound;
		}
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] < 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] >= tx_power_index_offest_lower_bound)) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
		tx_cck_bb_swing_index = cali_info->default_cck_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] < 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] < tx_power_index_offest_lower_bound)) {
		tx_agc_index = tx_power_index_offest_lower_bound;
		cali_info->remnant_ofdm_swing_idx[rf_path] = cali_info->absolute_ofdm_swing_idx[rf_path] - tx_power_index_offest_lower_bound;

		if (cali_info->default_ofdm_index > (cali_info->remnant_ofdm_swing_idx[rf_path] * (-1))) {
			tx_bb_swing_index = cali_info->default_ofdm_index + cali_info->remnant_ofdm_swing_idx[rf_path];
			tx_cck_bb_swing_index = cali_info->default_cck_index + cali_info->remnant_ofdm_swing_idx[rf_path];
		} else {
			tx_bb_swing_index = bb_swing_lower_bound;
			tx_cck_bb_swing_index = cali_info->default_cck_index;
		}
	}

	cali_info->remnant_cck_swing_idx = tx_agc_index;
	cali_info->remnant_ofdm_swing_idx[rf_path] = tx_agc_index;
	cali_info->bb_swing_idx_cck = tx_cck_bb_swing_index;
	cali_info->bb_swing_idx_ofdm[rf_path] = tx_bb_swing_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "MixMode Offset Path=%d pRF->absolute_ofdm_swing_idx[rf_path]=%d cali_info->remnant_ofdm_swing_idx[rf_path]=%d  pRF->bb_swing_idx_ofdm[rf_path]=%d   TxPwrIdxOffestUpper=%d   TxPwrIdxOffestLower=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->remnant_ofdm_swing_idx[rf_path],
	       cali_info->bb_swing_idx_ofdm[rf_path],
	       tx_power_index_offest_upper_bound,
	       tx_power_index_offest_lower_bound);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "MixMode Offset Path=%d pRF->absolute_ofdm_swing_idx[rf_path]=%d cali_info->remnant_cck_swing_idx=%d  pRF->bb_swing_idx_cck=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->remnant_cck_swing_idx,
	       cali_info->bb_swing_idx_cck);

	return true;
}


void odm_tx_pwr_track_set_pwr_8710c(
	void *dm_void,
	enum pwrtrack_method method,
	u8 rf_path,
	u8 channel_mapped_index)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);
	struct _hal_rf_ *rf = &(dm->rf_table);
	u8 pwr_tracking_limit_ofdm = 32;
	u8 pwr_tracking_limit_cck = 36;
	u8 tx_rate = 0xff;
	u8 final_ofdm_swing_index = 0;
	u8 final_cck_swing_index = 0;
	u8 i = 0;
	u8 channel = *dm->channel;
	u8 band_width = *dm->band_width;
	u8 tx_power_index_offest_upper_bound = 0;
	s8 tx_power_index_offest_lower_bound = 0;
	u8 tx_power_index = 0;

	if (*dm->mp_mode) {
		tx_rate = phydm_get_hwrate_to_mrate(dm, *rf->mp_rate_index);
	} else {
		u16 rate = *dm->forced_data_rate;

		if (!rate) { /*auto rate*/
			if (dm->number_linked_client != 0)
				tx_rate = phydm_get_hwrate_to_mrate(dm, dm->tx_rate);
			else
				tx_rate = rf->p_rate_index;
		} else   /*force rate*/
			tx_rate = (u8)rate;
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "======>%s tx_rate=0x%x\n", __func__, tx_rate);

#if 0
	if (tx_rate != 0xFF) {
		/*CCK*/
		if ((tx_rate >= ODM_MGN_1M && tx_rate <= ODM_MGN_5_5M) || tx_rate == ODM_MGN_11M)
			pwr_tracking_limit_cck = 36;
		/*OFDM*/
		else if ((tx_rate >= ODM_MGN_6M) && (tx_rate <= ODM_MGN_48M))
			pwr_tracking_limit_ofdm = 32;
		else if (tx_rate == ODM_MGN_54M)
			pwr_tracking_limit_ofdm = 32;
		/* HT*/
		else if ((tx_rate >= ODM_MGN_MCS0) && (tx_rate <= ODM_MGN_MCS2))
			pwr_tracking_limit_ofdm = 32;
		else if ((tx_rate >= ODM_MGN_MCS3) && (tx_rate <= ODM_MGN_MCS4))
			pwr_tracking_limit_ofdm = 32;
		else if ((tx_rate >= ODM_MGN_MCS5) && (tx_rate <= ODM_MGN_MCS7))
			pwr_tracking_limit_ofdm = 32;
		else
			pwr_tracking_limit_ofdm = cali_info->default_ofdm_index;
	}
#endif

	cali_info->remnant_cck_swing_idx = 0;
	cali_info->remnant_ofdm_swing_idx[rf_path] = 0;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       " cali_info->default_ofdm_index=%d,  cali_info->DefaultCCKIndex=%d, cali_info->absolute_ofdm_swing_idx[rf_path]=%d rf_path = %d\n",
	       cali_info->default_ofdm_index,
	       cali_info->default_cck_index,
	       cali_info->absolute_ofdm_swing_idx[rf_path],
	       rf_path);

	if (method == TXAGC) {
		cali_info->remnant_cck_swing_idx = cali_info->absolute_ofdm_swing_idx[rf_path];
		cali_info->remnant_ofdm_swing_idx[rf_path] = cali_info->absolute_ofdm_swing_idx[rf_path];

		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, CCK);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, OFDM);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, HT_MCS0_MCS7);

	} else if (method == BBSWING) {
		final_ofdm_swing_index = cali_info->default_ofdm_index + cali_info->absolute_ofdm_swing_idx[rf_path];
		final_cck_swing_index = cali_info->default_cck_index + cali_info->absolute_ofdm_swing_idx[rf_path];

		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, CCK);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, OFDM);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, HT_MCS0_MCS7);

		/* Adjust BB swing by OFDM IQ matrix */
		if (final_ofdm_swing_index >= OFDM_03DB_TABLE_SIZE_8710C)
			final_ofdm_swing_index = OFDM_03DB_TABLE_SIZE_8710C - 1;
		else if (final_ofdm_swing_index < 0)
			final_ofdm_swing_index = 0;

		if (final_cck_swing_index >= CCK_03DB_TABLE_SIZE_8710C)
			final_cck_swing_index = CCK_03DB_TABLE_SIZE_8710C - 1;
		else if (cali_info->bb_swing_idx_cck < 0)
			final_cck_swing_index = 0;

		odm_set_bb_reg(dm, R_0xcc8, 0x000007ff, ofdm_swing_table_03DB_8710c[final_ofdm_swing_index]);
		odm_set_bb_reg(dm, R_0xab4, 0x000007ff, cck_swing_table_03db_ch1_ch14_8710c[final_cck_swing_index]);

	} else if (method == MIX_MODE) {
		tx_power_index = odm_get_tx_power_index(dm, (enum rf_path)rf_path, tx_rate, band_width, channel);

		if (tx_power_index >= 127)
			tx_power_index = 127;

		tx_power_index_offest_upper_bound = 127 - tx_power_index;

		tx_power_index_offest_lower_bound = 0 - tx_power_index;
		
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "tx_power_index=%d tx_power_index_offest_upper_bound=%d tx_power_index_offest_lower_bound=%d rf_path=%d\n",
		       tx_power_index, tx_power_index_offest_upper_bound,
		       tx_power_index_offest_lower_bound, rf_path);

		get_mix_mode_tx_agc_bbs_wing_offset_8710c(dm, method, rf_path,
			tx_power_index_offest_upper_bound,
			tx_power_index_offest_lower_bound);

		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, CCK);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, OFDM);
		odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A, *dm->channel, HT_MCS0_MCS7);

		odm_set_bb_reg(dm, R_0xcc8, 0x000007ff, ofdm_swing_table_03DB_8710c[cali_info->bb_swing_idx_ofdm[rf_path]]);
		odm_set_bb_reg(dm, R_0xab4, 0x000007ff, cck_swing_table_03db_ch1_ch14_8710c[cali_info->bb_swing_idx_cck]);
		
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "~~~~~~~~~~~~~~~ 0xcc8 = 0x%x 0xab4 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xcc8, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xab4, MASKDWORD));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "~~~~~~~~~~~~~~~ 0x86c = 0x%x 0xe00 = 0x%x 0xe04 = 0x%x 0xe10 = 0x%x 0xe14 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0x86c, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe00, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe04, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe10, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe14, MASKDWORD));

}

void get_delta_swing_table_8710c(
	void *dm_void,
	u8 **temperature_up_a,
	u8 **temperature_down_a,
	u8 **temperature_up_b,
	u8 **temperature_down_b)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 channel = *dm->channel;
	u8 tx_rate = 0xff;

	if (*dm->mp_mode) {
		tx_rate = phydm_get_hwrate_to_mrate(dm, *rf->mp_rate_index);
	} else {
		u16 rate = *dm->forced_data_rate;

		if (!rate) { /*auto rate*/
			if (dm->number_linked_client != 0)
				tx_rate = phydm_get_hwrate_to_mrate(dm, dm->tx_rate);
			else
				tx_rate = rf->p_rate_index;
		} else   /*force rate*/
			tx_rate = (u8)rate;
	}

	if (channel >= 1 && channel <= 14) {
		if (IS_CCK_RATE(tx_rate)) {
			*temperature_up_a = cali_info->delta_swing_table_idx_2g_cck_a_p;
			*temperature_down_a = cali_info->delta_swing_table_idx_2g_cck_a_n;
			*temperature_up_b = cali_info->delta_swing_table_idx_2g_cck_b_p;
			*temperature_down_b = cali_info->delta_swing_table_idx_2g_cck_b_n;
		} else {
			*temperature_up_a = cali_info->delta_swing_table_idx_2ga_p;
			*temperature_down_a = cali_info->delta_swing_table_idx_2ga_n;
			*temperature_up_b = cali_info->delta_swing_table_idx_2gb_p;
			*temperature_down_b = cali_info->delta_swing_table_idx_2gb_n;
		}
	}
}

void get_delta_swing_xtal_table_8710c(
	void *dm_void,
	s8 **temperature_up_xtal,
	s8 **temperature_down_xtal)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct	*cali_info = &dm->rf_calibrate_info;

	*temperature_up_xtal = cali_info->delta_swing_table_xtal_p;
	*temperature_down_xtal = cali_info->delta_swing_table_xtal_n;
}

void
odm_txxtaltrack_set_xtal_8710c(
	void *dm_void
)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct	*cali_info = &dm->rf_calibrate_info;
	s32 crystal_cap;

	crystal_cap = dm->dm_cfo_track.crystal_cap_default + cali_info->xtal_offset;

	if (crystal_cap < 0)
		crystal_cap = 0;
	else if (crystal_cap > 127)
		crystal_cap = 127;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "crystal_cap(%d) = default_crystal_cap(%d) + cali_info->xtal_offset(%d)\n",
	       crystal_cap, dm->dm_cfo_track.crystal_cap_default, cali_info->xtal_offset);

	/*odm_set_bb_reg(dm, REG_MAC_PHY_CTRL, 0xFFF000, (crystal_cap | (crystal_cap << 6)));*/
	phydm_set_crystalcap(dm, (u8)crystal_cap);

	/*RF_DBG(dm, DBG_RF_TX_PWR_TRACK,"crystal_cap(0x2c)  0x%X\n", odm_get_bb_reg(dm, REG_MAC_PHY_CTRL, 0xFFF000));*/
}



void
configure_txpower_track_8710c(struct txpwrtrack_cfg *config)
{
	config->swing_table_size_cck = CCK_TABLE_SIZE_8710C;
	config->swing_table_size_ofdm = OFDM_TABLE_SIZE;
	config->threshold_iqk = IQK_THRESHOLD;
	/*config->threshold_dpk = DPK_THRESHOLD;*/
	config->average_thermal_num = AVG_THERMAL_NUM_8710C;
	config->rf_path_count = 1;
	config->thermal_reg_addr = RF_T_METER_8710C;

	config->odm_tx_pwr_track_set_pwr = odm_tx_pwr_track_set_pwr_8710c;
	config->do_iqk = do_iqk_8710c;
	config->phy_lc_calibrate = halrf_lck_trigger;
	config->get_delta_swing_table = get_delta_swing_table_8710c;
	config->get_delta_swing_xtal_table = get_delta_swing_xtal_table_8710c;
	config->odm_txxtaltrack_set_xtal = odm_txxtaltrack_set_xtal_8710c;
}

void
_phy_lc_calibrate_8710c(struct dm_struct *dm, boolean is2T)
{
	u8 tmp_reg, bb_clk;
	u32 rf_amode = 0, rf_bmode = 0, lc_cal, cnt;

	RF_DBG(dm, DBG_RF_LCK, "LCK:Start!!!\n");

	/* 1.Check continuous TX and Packet TX */
	tmp_reg = odm_read_1byte(dm, 0xd03);

	/*2. Deal with contisuous TX case*/
	if ((tmp_reg & 0x70) != 0)
		odm_write_1byte(dm, 0xd03, tmp_reg & 0x8F);
	/*disable all continuous TX*/
	else
		/*2. Deal with Packet TX case*/
		odm_write_1byte(dm, REG_TXPAUSE, 0xFF);
		/* block all queues*/
	/*3. backup RF0x18*/
	lc_cal = odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK);

	/*4. Start LCK: RF reg18 bit15=1*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, 0x08000, 0x1);

	for (cnt = 0; cnt < 100; cnt++) {
		if (odm_get_rf_reg(dm, RF_PATH_A, 0xab, 0x80000) == 0x1)
			break;
		ODM_delay_ms(10);
	}

	/*5. Recover channel number*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK, lc_cal);

	/*6. Restore original situation*/
	if ((tmp_reg & 0x70) != 0) {
		/*Deal with contisuous TX case*/
		odm_write_1byte(dm, 0xd03, tmp_reg);
	} else {
		/* Deal with Packet TX case*/
		odm_write_1byte(dm, REG_TXPAUSE, 0x00);
	}
	RF_DBG(dm, DBG_RF_LCK, "LCK:Stop!!!\n");
}

void
phy_lc_calibrate_8710c(void *dm_void)
{
	boolean is_single_tone = false, is_carrier_suppression = false;
	u32 timeout = 2000, timecount = 0;
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;

	/*Before IC IQK develop, call void functions! Only for compile test!*/
	//printf("%s %d TODO\r\n", __func__, __LINE__);
	return;

#if (DM_ODM_SUPPORT_TYPE & (ODM_WIN))
	if (odm_check_power_status(dm) == false)
		return;
#endif

#if (MP_DRIVER)
	if (*dm->mp_mode &&
	    ((*rf->is_con_tx || *rf->is_single_tone ||
	     *rf->is_carrier_suppresion)))
		return;
#endif

#if DISABLE_BB_RF
	return;
#endif

#if (DM_ODM_SUPPORT_TYPE & (ODM_CE | ODM_IOT))
	if (!(rf->rf_supportability & HAL_RF_IQK))
		return;
#endif
	while (*dm->is_scan_in_process) {
		RF_DBG(dm, DBG_RF_LCK, "[LCK]scan is in process, bypass LCK\n");
		return;
#if 0
		/*driect return or timecount+?*/
		ODM_delay_ms(50);
		timecount += 50;
#endif
	}
	dm->rf_calibrate_info.is_lck_in_progress = true;
	RF_DBG(dm, DBG_RF_LCK, "LCK start!!!\n");
	_phy_lc_calibrate_8710c(dm, false);
	dm->rf_calibrate_info.is_lck_in_progress = false;
	RF_DBG(dm, DBG_RF_LCK, "LCK:Finish!!!\n");
}

void phy_set_rf_path_switch_8710c(
	struct dm_struct *dm,
	boolean is_main)
{
#if 1
	//printf("%s %d TODO\r\n", __func__, __LINE__);
	return;
#else
	u32 sysreg408 = HAL_READ32(SYSTEM_CTRL_BASE_LP, 0x0408);
	sysreg408 &=~0x0000001F;
	sysreg408 |= 0x12;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, 0x0408, sysreg408);

	u32 sysreg410 = HAL_READ32(SYSTEM_CTRL_BASE_LP, 0x0410);
	sysreg410 &=~0x0000001F;
	sysreg410 |= 0x12;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, 0x0410, sysreg410);

	u32 sysreg208 = HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_LP_FUNC_EN0);
	sysreg208 |= BIT(28);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_LP_FUNC_EN0, sysreg208);	

	
	u32 sysreg344 = HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL);
	sysreg344 |= BIT(9);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);	


	u32 sysreg280 = HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_LP_SYSPLL_CTRL0);
	sysreg280 |= 0x7;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_LP_SYSPLL_CTRL0, sysreg280);	

	sysreg344 |= BIT(8);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);	

	sysreg344 |= BIT(0);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);	

	odm_set_bb_reg(dm, 0x930, 0x0000FF00, 0x98); 
	odm_set_bb_reg(dm, 0x870, 0x00000300, 0x3); 
	odm_set_bb_reg(dm, 0x944, 0x0000000C, 0x3); 

	//odm_set_bb_reg(dm, 0x860, 0x0000FF00, 0x98); 

	if (is_main)
		odm_set_bb_reg(dm, 0x860, 0x300, 0x1); /*mp_setrfpath 1*/
	else
		odm_set_bb_reg(dm, 0x860, 0x300, 0x2); /*mp_setrfpath 0*/
#endif
}


void phy_poll_lck_8710c(struct dm_struct *dm)
{
	u8 counter = 0x0;
	u32 temp;

	//printf("%s %d TODO\r\n", __func__, __LINE__);
	return;

	while (1) {
		temp = odm_get_rf_reg(dm, RF_PATH_A, 0xab, 0x80000);/*LCK_OK_BB, regAB[19]*/
		if (temp || counter > 49)
			break;
		counter++;
		ODM_delay_ms(1);
	};
	RF_DBG(dm, DBG_RF_LCK, "[LCK]counter = %d\n", counter);
}

#endif
