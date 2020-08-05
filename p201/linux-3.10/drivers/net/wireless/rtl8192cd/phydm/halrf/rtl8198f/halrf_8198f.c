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
void halrf_rf_lna_setting_8198f(struct dm_struct *dm_void,
				enum halrf_lna_set type)
{
#if 0
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 path = 0x0;

	for (path = 0x0; path < 2; path++) {
		if (type == phydm_lna_disable) {
			/*S0*/
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(19),
				       0x1);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33,
				       RFREGOFFSETMASK, 0x00003);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x3e,
				       RFREGOFFSETMASK, 0x00064);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x3f,
				       RFREGOFFSETMASK, 0x0afce);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(19),
				       0x0);
		} else if (type == phydm_lna_enable) {
			/*S0*/
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(19),
				       0x1);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33,
				       RFREGOFFSETMASK, 0x00003);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x3e,
				       RFREGOFFSETMASK, 0x00064);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x3f,
				       RFREGOFFSETMASK, 0x1afce);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(19),
				       0x0);
		}
	}
#endif
}

#if 0
boolean get_mix_mode_tx_agc_bb_swing_offset_8198f(void *dm_void,
						  enum pwrtrack_method method,
						  u8 rf_path,
						  u8 tx_power_index_offest)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 bb_swing_upper_bound = cali_info->default_ofdm_index + 10;
	u8 bb_swing_lower_bound = 0;

	s8 tx_agc_index = 0;
	u8 tx_bb_swing_index = cali_info->default_ofdm_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "Path_%d cali_info->absolute_ofdm_swing_idx[rf_path]=%d, tx_power_index_offest=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       tx_power_index_offest);

	if (tx_power_index_offest > 0XF)
		tx_power_index_offest = 0XF;

	if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 &&
	    cali_info->absolute_ofdm_swing_idx[rf_path] <=
		    tx_power_index_offest) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] >
		   tx_power_index_offest) {
		tx_agc_index = tx_power_index_offest;
		cali_info->remnant_ofdm_swing_idx[rf_path] =
			cali_info->absolute_ofdm_swing_idx[rf_path] -
			tx_power_index_offest;
		tx_bb_swing_index = cali_info->default_ofdm_index +
				    cali_info->remnant_ofdm_swing_idx[rf_path];

		if (tx_bb_swing_index > bb_swing_upper_bound)
			tx_bb_swing_index = bb_swing_upper_bound;
	} else {
		tx_agc_index = 0;

		if (cali_info->default_ofdm_index >
		    (cali_info->absolute_ofdm_swing_idx[rf_path] * (-1)))
			tx_bb_swing_index =
				cali_info->default_ofdm_index +
				cali_info->absolute_ofdm_swing_idx[rf_path];
		else
			tx_bb_swing_index = bb_swing_lower_bound;

		if (tx_bb_swing_index < bb_swing_lower_bound)
			tx_bb_swing_index = bb_swing_lower_bound;
	}

	cali_info->absolute_ofdm_swing_idx[rf_path] = tx_agc_index;
	cali_info->bb_swing_idx_ofdm[rf_path] = tx_bb_swing_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "MixMode Offset Path_%d   cali_info->absolute_ofdm_swing_idx[rf_path]=%d   cali_info->bb_swing_idx_ofdm[rf_path]=%d   tx_power_index_offest=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->bb_swing_idx_ofdm[rf_path], tx_power_index_offest);

	return true;
}
#endif

void odm_tx_pwr_track_set_pwr8198f(void *dm_void, enum pwrtrack_method method,
				   u8 rf_path, u8 channel_mapped_index)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);
	u32 bitmask_6_0 = BIT(6) | BIT(5) | BIT(4) | BIT(3) |
			BIT(2) | BIT(1) | BIT(0);
#if 0
#if (DM_ODM_SUPPORT_TYPE & ODM_IOT)
	struct _ADAPTER *adapter = dm->adapter;
	u8 channel = *dm->channel;
	u8 band_width = *dm->band_width;
#endif
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);
	struct _hal_rf_ *rf = &(dm->rf_table);
	u8 tx_power_index_offest_upper_bound = 0;
	s8 tx_power_index_offest_lower_bound = 0;
	u8 tx_power_index = 0;
	u8 tx_rate = 0xFF;

	if (*dm->mp_mode == 1) {
#ifdef CONFIG_MP_INCLUDED
		PMPT_CONTEXT mpt_ctx = &(adapter->mppriv.MptCtx);
		tx_rate = mpt_to_mgnt_rate(mpt_ctx->MptRateIndex);
#endif
	} else {
		u16 rate = *(dm->forced_data_rate);

		if (!rate) { /*auto rate*/
#if (DM_ODM_SUPPORT_TYPE & ODM_WIN)
			tx_rate = adapter->HalFunc.GetHwRateFromMRateHandler(dm->tx_rate);
#elif (DM_ODM_SUPPORT_TYPE & ODM_CE)
			if (dm->number_linked_client != 0)
				tx_rate = hw_rate_to_m_rate(dm->tx_rate);
			else
				tx_rate = rf->rate_index;
#endif
		} else /*force rate*/
			tx_rate = (u8)rate;
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "Call:%s tx_rate=0x%X\n", __func__, tx_rate);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->default_ofdm_index=%d   pRF->default_cck_index=%d\n", cali_info->default_ofdm_index, cali_info->default_cck_index);
#endif
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->absolute_ofdm_swing_idx=%d   pRF->remnant_ofdm_swing_idx=%d   pRF->absolute_cck_swing_idx=%d   pRF->remnant_cck_swing_idx=%d   rf_path=%d\n",
	       cali_info->absolute_ofdm_swing_idx[rf_path], cali_info->remnant_ofdm_swing_idx[rf_path], cali_info->absolute_cck_swing_idx[rf_path], cali_info->remnant_cck_swing_idx, rf_path);

#if 0
#if (DM_ODM_SUPPORT_TYPE & ODM_IOT)
	tx_power_index = odm_get_tx_power_index(dm, (enum rf_path)rf_path, tx_rate, band_width, channel);
#else
	/*0x04(TX_AGC_OFDM_6M)*/
	tx_power_index = config_phydm_read_txagc_8198f(dm, rf_path, 0x04);
#endif

	if (tx_power_index >= 127)
		tx_power_index = 127;

	tx_power_index_offest_upper_bound = 127 - tx_power_index;

	tx_power_index_offest_lower_bound = 0 - tx_power_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "tx_power_index=%d tx_power_index_offest_upper_bound=%d tx_power_index_offest_lower_bound=%d rf_path=%d\n", tx_power_index, tx_power_index_offest_upper_bound, tx_power_index_offest_lower_bound, rf_path);
#endif
	if (method == BBSWING) { /*use for mp driver clean power tracking status*/
		switch (rf_path) {
		case RF_PATH_A:
			odm_set_bb_reg(dm, R_0x18a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x18a0, odm_get_bb_reg(dm, R_0x18a0, bitmask_6_0));
			break;
		case RF_PATH_B:
			odm_set_bb_reg(dm, R_0x41a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x41a0, odm_get_bb_reg(dm, R_0x41a0, bitmask_6_0));
			break;
		case RF_PATH_C:
			odm_set_bb_reg(dm, R_0x52a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x52a0, odm_get_bb_reg(dm, R_0x52a0, bitmask_6_0));
			break;
		case RF_PATH_D:
			odm_set_bb_reg(dm, R_0x53a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x53a0, odm_get_bb_reg(dm, R_0x53a0, bitmask_6_0));
			break;
		default:
			break;
		}
	} else if (method == MIX_MODE) {
		switch (rf_path) {
		case RF_PATH_A:
			odm_set_bb_reg(dm, R_0x18a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x18a0, odm_get_bb_reg(dm, R_0x18a0, bitmask_6_0));
			break;
		case RF_PATH_B:
			odm_set_bb_reg(dm, R_0x41a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x41a0, odm_get_bb_reg(dm, R_0x41a0, bitmask_6_0));
			break;
		case RF_PATH_C:
			odm_set_bb_reg(dm, R_0x52a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x52a0, odm_get_bb_reg(dm, R_0x52a0, bitmask_6_0));
			break;
		case RF_PATH_D:
			odm_set_bb_reg(dm, R_0x53a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x53a0, odm_get_bb_reg(dm, R_0x53a0, bitmask_6_0));
			break;
		default:
			break;
		}	
	}
}

void get_delta_swing_table_8198f(
	void *dm_void,
	u8 **temperature_up_a,
	u8 **temperature_down_a,
	u8 **temperature_up_b,
	u8 **temperature_down_b,
	u8 **temperature_up_cck_a,
	u8 **temperature_down_cck_a,
	u8 **temperature_up_cck_b,
	u8 **temperature_down_cck_b
	)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);

	*temperature_up_cck_a = cali_info->delta_swing_table_idx_2g_cck_a_p;
	*temperature_down_cck_a = cali_info->delta_swing_table_idx_2g_cck_a_n;
	*temperature_up_cck_b = cali_info->delta_swing_table_idx_2g_cck_b_p;
	*temperature_down_cck_b = cali_info->delta_swing_table_idx_2g_cck_b_n;

	*temperature_up_a = cali_info->delta_swing_table_idx_2ga_p;
	*temperature_down_a = cali_info->delta_swing_table_idx_2ga_n;
	*temperature_up_b = cali_info->delta_swing_table_idx_2gb_p;
	*temperature_down_b = cali_info->delta_swing_table_idx_2gb_n;
}

void get_delta_swing_table_8198f_ex(
	void *dm_void,
	u8 **temperature_up_c,
	u8 **temperature_down_c,
	u8 **temperature_up_d,
	u8 **temperature_down_d,
	u8 **temperature_up_cck_c,
	u8 **temperature_down_cck_c,
	u8 **temperature_up_cck_d,
	u8 **temperature_down_cck_d
	)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);

	*temperature_up_cck_c = cali_info->delta_swing_table_idx_2g_cck_c_p;
	*temperature_down_cck_c = cali_info->delta_swing_table_idx_2g_cck_c_n;
	*temperature_up_cck_d = cali_info->delta_swing_table_idx_2g_cck_d_p;
	*temperature_down_cck_d = cali_info->delta_swing_table_idx_2g_cck_d_n;

	*temperature_up_c = cali_info->delta_swing_table_idx_2gc_p;
	*temperature_down_c = cali_info->delta_swing_table_idx_2gc_n;
	*temperature_up_d = cali_info->delta_swing_table_idx_2gd_p;
	*temperature_down_d = cali_info->delta_swing_table_idx_2gd_n;
}

void _phy_lc_calibrate_8198f(struct dm_struct *dm)
{
#if 0
	u32 lc_cal = 0, cnt = 0, tmp0xc00, tmp0xe00;

	RF_DBG(dm, DBG_RF_IQK, "[LCK]LCK start!!!!!!!\n");
	tmp0xc00 = odm_read_4byte(dm, 0xc00);
	tmp0xe00 = odm_read_4byte(dm, 0xe00);
	odm_write_4byte(dm, 0xc00, 0x4);
	odm_write_4byte(dm, 0xe00, 0x4);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, RFREGOFFSETMASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x0, RFREGOFFSETMASK, 0x10000);
	/*backup RF0x18*/
	lc_cal = odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK);
	/*disable RTK*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xc4, RFREGOFFSETMASK, 0x01402);
	/*Start LCK*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK,
		       lc_cal | 0x08000);
	ODM_delay_ms(100);
	for (cnt = 0; cnt < 100; cnt++) {
		if (odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, 0x8000) != 0x1)
			break;
		ODM_delay_ms(10);
	}
	/*Recover channel number*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK, lc_cal);
	/*enable RTK*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xc4, RFREGOFFSETMASK, 0x81402);
	/**restore*/
	odm_write_4byte(dm, 0xc00, tmp0xc00);
	odm_write_4byte(dm, 0xe00, tmp0xe00);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, RFREGOFFSETMASK, 0x3ffff);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x0, RFREGOFFSETMASK, 0x3ffff);
	RF_DBG(dm, DBG_RF_IQK, "[LCK]LCK end!!!!!!!\n");
#endif
}

/*LCK VERSION:0x1*/
void phy_lc_calibrate_8198f(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	_phy_lc_calibrate_8198f(dm);
}

void configure_txpower_track_8198f(struct txpwrtrack_cfg *config)
{
	config->swing_table_size_cck = TXSCALE_TABLE_SIZE;
	config->swing_table_size_ofdm = TXSCALE_TABLE_SIZE;
	config->threshold_iqk = IQK_THRESHOLD;
	config->threshold_dpk = DPK_THRESHOLD;
	config->average_thermal_num = AVG_THERMAL_NUM_8198F;
	config->rf_path_count = MAX_PATH_NUM_8198F;
	config->thermal_reg_addr = RF_T_METER_8198F;

	config->odm_tx_pwr_track_set_pwr = odm_tx_pwr_track_set_pwr8198f;
	config->do_iqk = do_iqk_8198f;
	config->phy_lc_calibrate = halrf_lck_trigger;

	config->get_delta_all_swing_table = get_delta_swing_table_8198f;
	config->get_delta_all_swing_table_ex = get_delta_swing_table_8198f_ex;
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
void phy_set_rf_path_switch_8198f(struct dm_struct *dm, boolean is_main)
#else
void phy_set_rf_path_switch_8198f(void *adapter, boolean is_main)
#endif
{
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
	HAL_DATA_TYPE *hal_data = GET_HAL_DATA(((PADAPTER)adapter));
	struct dm_struct *dm = &hal_data->DM_OutSrc;
#endif
#endif
	/*BY SY Request */
	odm_set_bb_reg(dm, R_0x4c, (BIT(24) | BIT(23)), 0x2);

	odm_set_bb_reg(dm, R_0x974, 0xff, 0xff);

	/*odm_set_bb_reg(dm, R_0x1991, 0x3, 0x0);*/
	odm_set_bb_reg(dm, R_0x1990, (BIT(9) | BIT(8)), 0x0);

	/*odm_set_bb_reg(dm, R_0xcbe, 0x8, 0x0);*/
	odm_set_bb_reg(dm, R_0xcbc, BIT(19), 0x0);

	odm_set_bb_reg(dm, R_0xcb4, 0xff, 0x77);

	odm_set_bb_reg(dm, R_0x70, MASKBYTE3, 0x0e);
	odm_set_bb_reg(dm, R_0x1704, MASKDWORD, 0x0000ff00);
	odm_set_bb_reg(dm, R_0x1700, MASKDWORD, 0xc00f0038);

	if (is_main) {
		/*odm_set_bb_reg(dm, R_0xcbd, 0x3, 0x2);		WiFi */
		odm_set_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8)), 0x2); /*WiFi */
	} else {
		/*odm_set_bb_reg(dm, R_0xcbd, 0x3, 0x1);	 BT*/
		odm_set_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8)), 0x1); /*BT*/
	}
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
boolean _phy_query_rf_path_switch_8198f(struct dm_struct *dm)
#else
boolean _phy_query_rf_path_switch_8198f(void *adapter)
#endif
{
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
	HAL_DATA_TYPE *hal_data = GET_HAL_DATA(((PADAPTER)adapter));
	struct dm_struct *dm = &hal_data->DM_OutSrc;
#endif
#endif
	if (odm_get_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8))) == 0x2) /*WiFi */
		return true;
	else
		return false;
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
boolean phy_query_rf_path_switch_8198f(struct dm_struct *dm)
#else
boolean phy_query_rf_path_switch_8198f(void *adapter)
#endif
{
#if DISABLE_BB_RF
	return true;
#endif
#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
	return _phy_query_rf_path_switch_8198f(dm);
#else
	return _phy_query_rf_path_switch_8198f(adapter);
#endif
}

#endif /* (RTL8198F_SUPPORT == 0)*/
