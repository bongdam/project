/*
 *****************************************************************************
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
 ****************************************************************************
 */

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
void halrf_rf_lna_setting_8195b(struct dm_struct *p_dm_void, enum halrf_lna_set type)
{
	struct dm_struct *p_dm = (struct dm_struct *)p_dm_void;
	u8 path = 0x0;

	if (type == HALRF_LNA_DISABLE) {
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xef, BIT(19), 0x1);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x33, RFREGOFFSETMASK, 0x00003);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3e, RFREGOFFSETMASK, 0x00064);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3f, RFREGOFFSETMASK, 0x0afce);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xef, BIT(19), 0x0);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xee, BIT(12), 0x1);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x33, RFREGOFFSETMASK, 0x00003);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3e, RFREGOFFSETMASK, 0x00064);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3f, RFREGOFFSETMASK, 0x0280d);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xee, BIT(12), 0x0);
	} else if (type == HALRF_LNA_ENABLE) {
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xef, BIT(19), 0x1);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x33, RFREGOFFSETMASK, 0x00003);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3e, RFREGOFFSETMASK, 0x00064);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3f, RFREGOFFSETMASK, 0x1afce);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xef, BIT(19), 0x0);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xee, BIT(12), 0x1);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x33, RFREGOFFSETMASK, 0x00003);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3e, RFREGOFFSETMASK, 0x00064);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0x3f, RFREGOFFSETMASK, 0x0281d);
		odm_set_rf_reg(p_dm, (enum rf_path)path, 0xee, BIT(12), 0x0);
	}
}

boolean
get_mix_mode_tx_agc_bbs_wing_offset_8195b(
	void *p_dm_void,
	enum pwrtrack_method method,
	u8 rf_path,
	u8 tx_power_index_offest_upper_bound,
	s8 tx_power_index_offest_lower_bound)
{
	struct dm_struct *p_dm = (struct dm_struct *)p_dm_void;
	struct dm_rf_calibration_struct *cali_info = &p_dm->rf_calibrate_info;

	u8 bb_swing_upper_bound = cali_info->default_ofdm_index + 12;
	u8 bb_swing_lower_bound = 0;

	s8 tx_agc_index = 0;
	u8 tx_bb_swing_index = cali_info->default_ofdm_index;

	if (bb_swing_upper_bound >= TXSCALE_TABLE_SIZE - 1)
		bb_swing_upper_bound = TXSCALE_TABLE_SIZE - 1;

	RF_DBG(p_dm, DBG_RF_TX_PWR_TRACK,
	       "Path_%d pRF->absolute_ofdm_swing_idx[rf_path]=%d, tx_power_index_offest_upper_bound=%d, tx_power_index_offest_lower_bound=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       tx_power_index_offest_upper_bound,
	       tx_power_index_offest_lower_bound);

	if (tx_power_index_offest_upper_bound > 0xf)
		tx_power_index_offest_upper_bound = 0xf;

	if (tx_power_index_offest_lower_bound < -15)
		tx_power_index_offest_lower_bound = -15;

	if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 && cali_info->absolute_ofdm_swing_idx[rf_path] <= tx_power_index_offest_upper_bound) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] > tx_power_index_offest_upper_bound)) {
		tx_agc_index = tx_power_index_offest_upper_bound;
		cali_info->remnant_ofdm_swing_idx[rf_path] = cali_info->absolute_ofdm_swing_idx[rf_path] - tx_power_index_offest_upper_bound;
		tx_bb_swing_index = cali_info->default_ofdm_index + cali_info->remnant_ofdm_swing_idx[rf_path];

		if (tx_bb_swing_index > bb_swing_upper_bound)
			tx_bb_swing_index = bb_swing_upper_bound;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] < 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] >= tx_power_index_offest_lower_bound)) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] < 0 && (cali_info->absolute_ofdm_swing_idx[rf_path] < tx_power_index_offest_lower_bound)) {
		tx_agc_index = tx_power_index_offest_lower_bound;
		cali_info->remnant_ofdm_swing_idx[rf_path] = cali_info->absolute_ofdm_swing_idx[rf_path] - tx_power_index_offest_lower_bound;

		if (cali_info->default_ofdm_index > (cali_info->remnant_ofdm_swing_idx[rf_path] * (-1)))
			tx_bb_swing_index = cali_info->default_ofdm_index + cali_info->remnant_ofdm_swing_idx[rf_path];
		else
			tx_bb_swing_index = bb_swing_lower_bound;
	}

	cali_info->absolute_ofdm_swing_idx[rf_path] = tx_agc_index;
	cali_info->bb_swing_idx_ofdm[rf_path] = tx_bb_swing_index;

	RF_DBG(p_dm, DBG_RF_TX_PWR_TRACK,
	       "MixMode Offset Path_%d   pRF->absolute_ofdm_swing_idx[rf_path]=%d   pRF->bb_swing_idx_ofdm[rf_path]=%d   TxPwrIdxOffestUpper=%d   TxPwrIdxOffestLower=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->bb_swing_idx_ofdm[rf_path],
	       tx_power_index_offest_upper_bound,
	       tx_power_index_offest_lower_bound);

	return true;
}

void odm_tx_pwr_track_set_pwr8195b(
	void *dm_void,
	enum pwrtrack_method method,
	u8 rf_path,
	u8 channel_mapped_index)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 channel = *dm->channel;
	u8 band_width = *dm->band_width;
	u8 tx_power_index_offest_upper_bound = 0;
	s8 tx_power_index_offest_lower_bound = 0;
	u8 tx_power_index = 0;
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

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "Call:%s tx_rate=0x%X\n", __func__,
	       tx_rate);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->default_ofdm_index=%d   pRF->default_cck_index=%d\n",
	       cali_info->default_ofdm_index,
	       cali_info->default_cck_index);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->absolute_ofdm_swing_idx=%d   pRF->remnant_ofdm_swing_idx=%d   pRF->absolute_cck_swing_idx=%d   pRF->remnant_cck_swing_idx=%d   rf_path=%d\n",
	       cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->remnant_ofdm_swing_idx[rf_path],
	       cali_info->absolute_cck_swing_idx[rf_path],
	       cali_info->remnant_cck_swing_idx, rf_path);

	tx_power_index = odm_get_tx_power_index(dm, (enum rf_path)rf_path, tx_rate, band_width, channel);

	if (tx_power_index >= 63)
		tx_power_index = 63;

	tx_power_index_offest_upper_bound = 63 - tx_power_index;

	tx_power_index_offest_lower_bound = 0 - tx_power_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "tx_power_index=%d tx_power_index_offest_upper_bound=%d tx_power_index_offest_lower_bound=%d rf_path=%d\n",
	       tx_power_index, tx_power_index_offest_upper_bound,
	       tx_power_index_offest_lower_bound, rf_path);

	/*use for mp driver clean power tracking status*/
	if (method == BBSWING) {
		switch (rf_path) {
		case RF_PATH_A:
			odm_set_bb_reg(dm, 0xC94, (BIT(6) | BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1)), ((cali_info->absolute_ofdm_swing_idx[rf_path]) & 0x3f));
			odm_set_bb_reg(dm, REG_A_TX_SCALE_JAGUAR, 0xFFE00000, tx_scaling_table_jaguar[cali_info->bb_swing_idx_ofdm[rf_path]]);
			break;

		default:
			break;
		}

	} else if (method == MIX_MODE) {
		switch (rf_path) {
		case RF_PATH_A:
			get_mix_mode_tx_agc_bbs_wing_offset_8195b(dm, method, rf_path, tx_power_index_offest_upper_bound, tx_power_index_offest_lower_bound);
			odm_set_bb_reg(dm, 0xc94, (BIT(6) | BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1)), ((cali_info->absolute_ofdm_swing_idx[rf_path]) & 0x3f));
			odm_set_bb_reg(dm, REG_A_TX_SCALE_JAGUAR, 0xFFE00000, tx_scaling_table_jaguar[cali_info->bb_swing_idx_ofdm[rf_path]]);

			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "TXAGC(0xC94)=0x%x BBSwing(0xc1c)=0x%x BBSwingIndex=%d rf_path=%d\n",
			       odm_get_bb_reg(dm, 0xC94,
			       (BIT(6) | BIT(5) | BIT(4) | BIT(3) | BIT(2) |
			       BIT(1))), odm_get_bb_reg(dm, 0xc1c, 0xFFE00000),
			       cali_info->bb_swing_idx_ofdm[rf_path],
			       rf_path);
			break;

		default:
			break;
		}
	}
}

void get_delta_swing_table_8195b(
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
	} else if (channel >= 36 && channel <= 64) {
		*temperature_up_a = cali_info->delta_swing_table_idx_5ga_p[0];
		*temperature_down_a = cali_info->delta_swing_table_idx_5ga_n[0];
		*temperature_up_b = cali_info->delta_swing_table_idx_5gb_p[0];
		*temperature_down_b = cali_info->delta_swing_table_idx_5gb_n[0];
	} else if (channel >= 100 && channel <= 144) {
		*temperature_up_a = cali_info->delta_swing_table_idx_5ga_p[1];
		*temperature_down_a = cali_info->delta_swing_table_idx_5ga_n[1];
		*temperature_up_b = cali_info->delta_swing_table_idx_5gb_p[1];
		*temperature_down_b = cali_info->delta_swing_table_idx_5gb_n[1];
	} else if (channel >= 149 && channel <= 177) {
		*temperature_up_a = cali_info->delta_swing_table_idx_5ga_p[2];
		*temperature_down_a = cali_info->delta_swing_table_idx_5ga_n[2];
		*temperature_up_b = cali_info->delta_swing_table_idx_5gb_p[2];
		*temperature_down_b = cali_info->delta_swing_table_idx_5gb_n[2];
	}
}

void get_delta_swing_xtal_table_8195b(
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
odm_txxtaltrack_set_xtal_8195b(
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

void _phy_aac_calibrate_8195b(
	struct dm_struct *dm)
{
	u32 cnt = 0;

	RF_DBG(dm, DBG_RF_IQK, "[AACK]AACK start!!!!!!!\n");
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_set_rf_reg(dm, RF_PATH_A, 0xa8, RFREGOFFSETMASK, 0x2fc17);
		ODM_delay_ms(1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x9b, RFREGOFFSETMASK, 0x01000);
		odm_set_rf_reg(dm, RF_PATH_A, 0x9b, RFREGOFFSETMASK, 0x01008);
		odm_set_rf_reg(dm, RF_PATH_A, 0x9b, RFREGOFFSETMASK, 0x0100c);
		//ODM_delay_ms(1);
		for (cnt = 0; cnt < 3; cnt++) {
			ODM_delay_us(200);
			if (odm_get_rf_reg(dm, RF_PATH_A, 0x9b, BIT(1)) != 0x1)
				break;
		}
		break;
	case ODM_BAND_5G:
		odm_set_rf_reg(dm, RF_PATH_A, 0xa8, RFREGOFFSETMASK, 0x8fc17);
		ODM_delay_ms(1);
		odm_set_rf_reg(dm, RF_PATH_A, 0xa2, RFREGOFFSETMASK, 0x04000);
		odm_set_rf_reg(dm, RF_PATH_A, 0xa2, RFREGOFFSETMASK, 0x04008);
		odm_set_rf_reg(dm, RF_PATH_A, 0xa2, RFREGOFFSETMASK, 0x0400c);
		for (cnt = 0; cnt < 3; cnt++) {
			ODM_delay_us(200);
			if (odm_get_rf_reg(dm, RF_PATH_A, 0xa2, BIT(1)) != 0x1)
				break;
		}
		ODM_delay_ms(1);
	break;
	}
	odm_set_rf_reg(dm, RF_PATH_A, 0xa8, RFREGOFFSETMASK, 0x0fc00);
	RF_DBG(dm, DBG_RF_IQK, "[AACK]AACK end!!!!!!!\n");
}

void _phy_lc_calibrate_8195b(
	struct dm_struct *dm)
{
#if 1
	RF_DBG(dm, DBG_RF_IQK, "[RTK]real-time RTK!!!!!!!\n");
	odm_set_rf_reg(dm, RF_PATH_A, 0xc1, RFREGOFFSETMASK, 0x02018);	
	odm_set_rf_reg(dm, RF_PATH_A, 0xc0, RFREGOFFSETMASK, 0x09324);
	odm_set_rf_reg(dm, RF_PATH_A, 0xc0, RFREGOFFSETMASK, 0x89324);
	odm_set_rf_reg(dm, RF_PATH_A, 0xc1, RFREGOFFSETMASK, 0x0201c);
	ODM_delay_ms(1);
	RF_DBG(dm, DBG_RF_IQK, "[RTK]real-time RTK!!!!!!!\n");
#endif

#if 0
	u32 lc_cal = 0, cnt = 0, tmp0xc00;
	/*RF to standby mode*/
	tmp0xc00 = odm_read_4byte(dm, 0xc00);
	odm_write_4byte(dm, 0xc00, 0x4);
	odm_set_rf_reg(dm, RF_PATH_A, 0x0, RFREGOFFSETMASK, 0x10000);

	_phy_aac_calibrate_8195b(dm);

	/*backup RF0x18*/
	lc_cal = odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK);
	/*Start LCK*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK, lc_cal | 0x08000);
	ODM_delay_ms(50);

	for (cnt = 0; cnt < 100; cnt++) {
		if (odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, 0x8000) != 0x1)
			break;
		ODM_delay_ms(10);
	}

	/*Recover channel number*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK, lc_cal);
	/**restore*/
	odm_write_4byte(dm, 0xc00, tmp0xc00);
	odm_set_rf_reg(dm, RF_PATH_A, 0x0, RFREGOFFSETMASK, 0x3ffff);
	RF_DBG(dm, DBG_RF_IQK, ("[LCK]LCK end!!!!!!!\n"));
#endif
}

/*LCK:0x1*/
void phy_lc_calibrate_8195b(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	_phy_aac_calibrate_8195b(dm);
	_phy_lc_calibrate_8195b(dm);
}

void configure_txpower_track_8195b(
	struct txpwrtrack_cfg *config)
{
	config->swing_table_size_cck = TXSCALE_TABLE_SIZE;
	config->swing_table_size_ofdm = TXSCALE_TABLE_SIZE;
	config->threshold_iqk = IQK_THRESHOLD;
	config->threshold_dpk = DPK_THRESHOLD;
	config->average_thermal_num = AVG_THERMAL_NUM_8195B;
	config->average_thermal_num = 0x4;
	config->rf_path_count = MAX_PATH_NUM_8195B;
	config->thermal_reg_addr = RF_T_METER_8195B;
	config->thermal_reg_addr = 0x42;

	config->odm_tx_pwr_track_set_pwr = odm_tx_pwr_track_set_pwr8195b;
	config->do_iqk = do_iqk_8195b;
	config->phy_lc_calibrate = phy_lc_calibrate_8195b;
	config->get_delta_swing_table = get_delta_swing_table_8195b;
	config->get_delta_swing_xtal_table = get_delta_swing_xtal_table_8195b;
	config->odm_txxtaltrack_set_xtal = odm_txxtaltrack_set_xtal_8195b;
}

void phy_set_rf_path_switch_8195b(
	struct dm_struct *dm,
	boolean is_main)
{
	odm_set_bb_reg(dm, 0xcb4, (BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x7); /*DPDT_SEL_N set to be 0*/
	odm_set_bb_reg(dm, 0xcb4, (BIT(7) | BIT(6) | BIT(5) | BIT(4)), 0x7); /*DPDT_SEL_P set to be 0*/
	odm_set_bb_reg(dm, 0xcb4, (BIT(29) | BIT(28)), 0x1); /*invert DPDT_SEL_N*/

	if (is_main)
		odm_set_bb_reg(dm, 0xcb4, (BIT(29) | BIT(28)), 0x1); /*invert DPDT_SEL_N*/
	else
		odm_set_bb_reg(dm, 0xcb4, (BIT(29) | BIT(28)), 0x2); /*invert DPDT_SEL_P*/
}

boolean phy_query_rf_path_switch_8195b(
	struct dm_struct *dm)
{
#if DISABLE_BB_RF
	return true;
#endif
	ODM_delay_ms(300);

	if (odm_get_bb_reg(dm, 0xcb4, (BIT(29) | BIT(28))) == 0x1) /*WiFi */
		return true;
	else
		return false;
}
#endif /*#if (RTL8195B_SUPPORT == 1)*/
