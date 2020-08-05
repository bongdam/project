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
void halrf_rf_lna_setting_8814b(struct dm_struct *dm_void,
				enum halrf_lna_set type)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 path = 0x0;

	for (path = 0x0; path < 2; path++)
		if (type == HALRF_LNA_DISABLE) {
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
		} else if (type == HALRF_LNA_ENABLE) {
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

#if 0
boolean get_mix_mode_tx_agc_bb_swing_offset_8814b(void *dm_void,
						  enum pwrtrack_method method,
						  u8 rf_path,
						  u8 tx_power_index_offset)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 bb_swing_upper_bound = cali_info->default_ofdm_index + 10;
	u8 bb_swing_lower_bound = 0;

	s8 tx_agc_index = 0;
	u8 tx_bb_swing_index = cali_info->default_ofdm_index;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "Path_%d absolute_ofdm_swing[%d]=%d tx_power_idx_offset=%d\n",
	       rf_path, rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       tx_power_index_offset);

	if (tx_power_index_offset > 0XF)
		tx_power_index_offset = 0XF;

	if (cali_info->absolute_ofdm_swing_idx[rf_path] >= 0 &&
	    cali_info->absolute_ofdm_swing_idx[rf_path] <=
		    tx_power_index_offset) {
		tx_agc_index = cali_info->absolute_ofdm_swing_idx[rf_path];
		tx_bb_swing_index = cali_info->default_ofdm_index;
	} else if (cali_info->absolute_ofdm_swing_idx[rf_path] >
		   tx_power_index_offset) {
		tx_agc_index = tx_power_index_offset;
		cali_info->remnant_ofdm_swing_idx[rf_path] =
			cali_info->absolute_ofdm_swing_idx[rf_path] -
			tx_power_index_offset;
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
	       "absolute_ofdm[%d]=%d bb_swing_ofdm[%d]=%d tx_pwr_offset=%d\n",
	       rf_path, cali_info->absolute_ofdm_swing_idx[rf_path],
	       rf_path, cali_info->bb_swing_idx_ofdm[rf_path],
	       tx_power_index_offset);

	return true;
}
#endif

u8 _halrf_tssi_rate_to_driver_rate_8814b(
	void *dm_void, u8 rate)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 driver_rate = 0;
		
	if (rate == 0)
		driver_rate = ODM_MGN_1M;
	else if (rate == 1)
		driver_rate = ODM_MGN_2M;
	else if (rate == 2)
		driver_rate = ODM_MGN_5_5M;
	else if (rate == 3)
		driver_rate = ODM_MGN_11M;
	else if (rate == 4)
		driver_rate = ODM_MGN_6M;
	else if (rate == 5)
		driver_rate = ODM_MGN_9M;
	else if (rate == 6)
		driver_rate = ODM_MGN_12M;
	else if (rate == 7)
		driver_rate = ODM_MGN_18M;
	else if (rate == 8)
		driver_rate = ODM_MGN_24M;
	else if (rate == 9)
		driver_rate = ODM_MGN_36M;
	else if (rate == 10)
		driver_rate = ODM_MGN_48M;
	else if (rate == 11)
		driver_rate = ODM_MGN_54M;
	else if (rate >= 12 && rate <= 83)
		driver_rate = rate + ODM_MGN_MCS0 - 12;
	else
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s not exit tx rate\n", __func__);

	return driver_rate;
}

u8 _halrf_driver_rate_to_tssi_rate_8814b(
	void *dm_void, u8 rate)
{
	u8 tssi_rate = 0;
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	if (rate == ODM_MGN_1M)
		tssi_rate = 0;
	else if (rate == ODM_MGN_2M)
		tssi_rate = 1;
	else if (rate == ODM_MGN_5_5M)
		tssi_rate = 2;
	else if (rate == ODM_MGN_11M)
		tssi_rate = 3;
	else if (rate == ODM_MGN_6M)
		tssi_rate = 4;
	else if (rate == ODM_MGN_9M)
		tssi_rate = 5;
	else if (rate == ODM_MGN_12M)
		tssi_rate = 6;
	else if (rate == ODM_MGN_18M)
		tssi_rate = 7;
	else if (rate == ODM_MGN_24M)
		tssi_rate = 8;
	else if (rate == ODM_MGN_36M)
		tssi_rate = 9;
	else if (rate == ODM_MGN_48M)
		tssi_rate = 10;
	else if (rate == ODM_MGN_54M)
		tssi_rate = 11;
	else if (rate >= ODM_MGN_MCS0 && rate <= ODM_MGN_VHT4SS_MCS9)
		tssi_rate = rate - ODM_MGN_MCS0 + 12;
	else
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s not exit tx rate\n", __func__);
	return tssi_rate;
}

void _backup_bb_registers_8814b(
	void *dm_void,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = odm_get_bb_reg(dm, reg[i], MASKDWORD);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Backup BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
	}
}

void _reload_bb_registers_8814b(
	void *dm_void,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)

{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		odm_set_bb_reg(dm, reg[i], MASKDWORD, reg_backup[i]);
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Reload BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
	}
}

void _backup_rf_registers_8814b(
	void *dm_void,
	u8 e_rf_path,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = odm_get_rf_reg(dm, e_rf_path, reg[i], MASKDWORD);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Backup RF 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
	}
}

void _reload_rf_registers_8814b(
	void *dm_void,
	u8 e_rf_path,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)

{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		odm_set_rf_reg(dm, e_rf_path, reg[i], MASKDWORD, reg_backup[i]);
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Reload RF 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
	}
}

void _backup_syn_registers_8814b(
	void *dm_void,
	enum rf_syn syn_path,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = config_phydm_read_syn_reg_8814b(dm, syn_path, reg[i], RFREGOFFSETMASK);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Backup SYN%d 0x%x = 0x%x\n",
		       syn_path, reg[i], reg_backup[i]);
	}
}

void _reload_syn_registers_8814b(
	void *dm_void,
	enum rf_syn syn_path,
	u32 *reg,
	u32 *reg_backup,
	u32 reg_num)

{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i;

	for (i = 0; i < reg_num; i++) {
		config_phydm_write_rf_syn_8814b(dm, syn_path, reg[i], RFREGOFFSETMASK, reg_backup[i]);
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI] Reload SYN%d 0x%x = 0x%x\n",
		       syn_path, reg[i], reg_backup[i]);
	}
}

u32 _halrf_get_efuse_tssi_offset_8814b(
	void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;
	u32 offset = 0;
	u32 offset_index = 0;

	if (channel >= 1 && channel <= 2)	/*2G MCS 40M*/
		offset_index = 6;
	else if (channel >= 3 && channel <= 5)
		offset_index = 7;
	else if (channel >= 6 && channel <= 8)
		offset_index = 8;
	else if (channel >= 9 && channel <= 11)
		offset_index = 9;
	else if (channel >= 12 && channel <= 14)
		offset_index = 10;
	else if (channel >= 36 && channel <= 40)	/*5G MCS 40M*/
		offset_index = 11;
	else if (channel >= 42 && channel <= 48)
		offset_index = 12;
	else if (channel >= 50 && channel <= 58)
		offset_index = 13;
	else if (channel >= 60 && channel <= 64)
		offset_index = 14;
	else if (channel >= 100 && channel <= 104)
		offset_index = 15;
	else if (channel >= 106 && channel <= 112)
		offset_index = 16;
	else if (channel >= 114 && channel <= 120)
		offset_index = 17;
	else if (channel >= 122 && channel <= 128)
		offset_index = 18;
	else if (channel >= 130 && channel <= 136)
		offset_index = 19;
	else if (channel >= 138 && channel <= 144)
		offset_index = 20;
	else if (channel >= 149 && channel <= 153)
		offset_index = 21;
	else if (channel >= 155 && channel <= 161)
		offset_index = 22;
	else if (channel >= 163 && channel <= 169)
		offset_index = 23;
	else if (channel >= 171 && channel <= 177)
		offset_index = 24;

	offset = (u32)tssi->tssi_efuse[path][offset_index];

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"=====>%s channel=%d offset_index(Chn Group)=%d offset=%d\n",
		__func__, channel, offset_index, offset);

	return offset;
}

void _halrf_driver_flash_to_tssi_de_8814b(
	void *dm_void)
{
#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	struct rtl8192cd_priv *priv = dm->priv;
	u8 i, j, offset_index = 0;
	u8 channel_to_index = 1;

	/*AP 2G CCK*/
	for (i = 0; i < 14; i++) {
		if (i == 1 - channel_to_index)
			offset_index = 0;
		else if (i == 3 - channel_to_index)
			offset_index = 1;
		else if (i == 6 - channel_to_index)
			offset_index = 2;
		else if (i == 9 - channel_to_index)
			offset_index = 3;
		else if (i == 12 - channel_to_index)
			offset_index = 4;
		else
			continue;

		tssi->tssi_efuse[0][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_A[i];
		tssi->tssi_efuse[1][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_B[i];
		tssi->tssi_efuse[2][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_C[i];
		tssi->tssi_efuse[3][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_D[i];
	}

	/*AP 2G MCS*/
	for (i = 0; i < 14; i++) {
		if (i == 1 - channel_to_index)
			offset_index = 6;
		else if (i == 3 - channel_to_index)
			offset_index = 7;
		else if (i == 6 - channel_to_index)
			offset_index = 8;
		else if (i == 9 - channel_to_index)
			offset_index = 9;
		else if (i == 12 - channel_to_index)
			offset_index = 10;
		else
			continue;

		tssi->tssi_efuse[0][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_A[i];
		tssi->tssi_efuse[1][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_B[i];
		tssi->tssi_efuse[2][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_C[i];
		tssi->tssi_efuse[3][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_D[i];
	}

	/*AP 5G MCS*/
	for (i = 0; i <= 177; i++) {
		if (i == 36)
			offset_index = 11;
		else if (i == 44)
			offset_index = 12;
		else if (i == 52)
			offset_index = 13;
		else if (i == 60)
			offset_index = 14;
		else if (i == 100)
			offset_index = 15;
		else if (i == 108)
			offset_index = 16;
		else if (i == 116)
			offset_index = 17;
		else if (i == 124)
			offset_index = 18;
		else if (i == 132)
			offset_index = 19;
		else if (i == 140)
			offset_index = 20;
		else if (i == 149)
			offset_index = 21;
		else if (i == 157)
			offset_index = 22;
		else if (i == 165)
			offset_index = 23;
		else if (i == 173)
			offset_index = 24;
		else
			continue;

		tssi->tssi_efuse[0][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_A[i];
		tssi->tssi_efuse[1][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_B[i];
		tssi->tssi_efuse[2][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_C[i];
		tssi->tssi_efuse[3][offset_index] = priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_D[i];
	}
#endif
}


void _halrf_tssi_set_de_by_thermal_8814b(void *dm_void, u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	u32 i;
	u32 addr_d[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 addr_d_bitmask[4] = {0xff000000, 0x3fc00000, 0x3fc00000, 0x3fc00000};
	u32 addr_cck_d[4] = {0x18e8, 0x1ef0, 0x1ef8, 0x1eb8};
	u32 addr_cck_d_bitmask[4] = {0x01fe0000, 0x0001fe00, 0x0001fe00, 0x7f800000};
	u32 tssi_offest_de, offset_index = 0;
	u8 channel = *dm->channel;
	s8 tssi_de_tmp;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "======>%s\n", __func__);

	if (dm->rf_calibrate_info.txpowertrack_control == 4) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"==>%s txpowertrack_control=%d return!!!\n", __func__,
			dm->rf_calibrate_info.txpowertrack_control);

		for (i = 0; i < MAX_PATH_NUM_8814B; i++) {
			odm_set_bb_reg(dm, addr_cck_d[i], addr_cck_d_bitmask[i], 0x0);
			odm_set_bb_reg(dm, addr_d[i], addr_d_bitmask[i], 0x0);
		}
		return;
	}

#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	if (channel >= 1 && channel <= 2)	/*AP 2G CCK*/
		offset_index = 0;
	else if (channel >= 3 && channel <= 5)
		offset_index = 1;
	else if (channel >= 6 && channel <= 8)
		offset_index = 2;
	else if (channel >= 9 && channel <= 11)
		offset_index = 3;
	else if (channel >= 12 && channel <= 14)
		offset_index = 4;
#else
	if (channel >= 1 && channel <= 2)	/*Windows/CE 2G CCK*/
		offset_index = 0;
	else if (channel >= 3 && channel <= 5)
		offset_index = 1;
	else if (channel >= 6 && channel <= 8)
		offset_index = 2;
	else if (channel >= 9 && channel <= 11)
		offset_index = 3;
	else if (channel >= 12 && channel <= 13)
		offset_index = 4;
	else if (channel == 14)
		offset_index = 5;
#endif

	tssi_de_tmp = tssi->tssi_efuse[rf_path][offset_index] + cali_info->absolute_ofdm_swing_idx[rf_path];
	odm_set_bb_reg(dm, addr_cck_d[rf_path], addr_cck_d_bitmask[rf_path],
		(tssi_de_tmp & 0xff));
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"CCK 0x%x[%x] tssi_de_tmp=%d absolute_ofdm_swing_idx=%d path=%d\n",
		addr_cck_d[rf_path], addr_cck_d_bitmask[rf_path], tssi_de_tmp, 
		cali_info->absolute_ofdm_swing_idx[rf_path], rf_path);

	tssi_offest_de = (u32)_halrf_get_efuse_tssi_offset_8814b(dm, rf_path);
	tssi_de_tmp = (s8)tssi_offest_de + cali_info->absolute_ofdm_swing_idx[rf_path];
	odm_set_bb_reg(dm, addr_d[rf_path], addr_d_bitmask[rf_path], (tssi_de_tmp & 0xff));
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"OFDM 0x%x[%x] tssi_de_tmp=%d absolute_ofdm_swing_idx=%d path=%d\n",
		addr_d[rf_path], addr_d_bitmask[rf_path], tssi_de_tmp,
		cali_info->absolute_ofdm_swing_idx[rf_path], rf_path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "<======%s\n", __func__);
}

void halrf_trigger_tssi_8814b(
	void *dm_void,
	u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel, finish_bit = 1;

	u32 delta_tssi_code, i, j;
	u32 big_a, small_a, slope;
	s32 tssi_txagc_offset[4], temp;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_setting[4] = {0x1830, 0x4130, 0x5230, 0x5330};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};

	big_a = odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, rf_path);
		rf->is_tssi_in_progress = 0;
		return;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a;			/* 1 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[rf_path], big_a_bit_mask[rf_path],
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       big_a, big_a_reg[rf_path], big_a_bit_mask[rf_path], rf_path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1*slope(%d) = 1000/small_a path=%d\n",
	       small_a, big_a, slope, rf_path);

	/*if (tssi->tssi_finish_bit[rf_path] == 0) {*/
	/*odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x0);*/
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "TSSI trigger bit 0x%x[28]=0x%x path=%d\n",
	       tssi_trigger[rf_path],
	       odm_get_bb_reg(dm, tssi_trigger[rf_path], 0x10000000),
	       rf_path);

	if (odm_get_bb_reg(dm, tssi_trigger[rf_path], 0x10000000) != 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"======>%s TSSI trigger bit == 1, return path=%d\n",
			__func__, rf_path);
		return;
	}

	odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x700b8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x706f0044);
	} else {
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x701f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x702f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x704f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x706f0042);
	}

	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x707b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x708b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x709b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70ab8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70bb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70cb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70db8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70eb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70fb8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x1);
	} else {
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x1);	
	}

	odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x0);
	odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x1);

#if 0
	for (i = 0; odm_get_bb_reg(dm, tssi_result[rf_path], 0x10000) == 0; i++) {
		ODM_delay_ms(1);
		/*RF_DBG(dm, DBG_RF_TX_PWR_TRACK,*/
		/*	 "TSSI finish bit != 1 retry=%d path=%d   0x%x\n", i, rf_path,*/
		/*	 odm_get_bb_reg(dm, tssi_result[rf_path], MASKDWORD));*/
		if (i >= 60) {
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "TSSI finish bit i > 60ms, return path=%d\n", rf_path);
			finish_bit = 0;
			break;
			/*rf->is_tssi_in_progress = 0;*/
			/*return;*/
		}
	}

#endif
}

u8 halrf_get_tssi_result_8814b(
	void *dm_void,
	u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;

	u32 delta_tssi_code;
	u32 big_a, small_a, slope;
	s32 tssi_txagc_offset[4], temp;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_result[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 txagc_offset[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};

	temp = odm_get_bb_reg(dm, tssi_result[rf_path], 0x10000);

	if (temp == 0) {
		tssi->tssi_finish_bit[rf_path] = 0;
		delta_tssi_code = 0;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"======>%s TSSI finish bit == 0, return path=%d !!!\n",
			__func__, rf_path);
		return 0;
	} else {
		tssi->tssi_finish_bit[rf_path] = 1;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "======>%s TSSI finish bit Ok path=%d !!!\n",
		       __func__, rf_path);
		
		delta_tssi_code = odm_get_bb_reg(dm, tssi_result[rf_path], 0x000001ff);
		odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x0);
	}

	big_a = odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, rf_path);
		rf->is_tssi_in_progress = 0;
		return 1;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a;			/* 1 * slope */

	if (delta_tssi_code & 0x100)
		tssi->delta_tssi_txagc_offset[rf_path] = delta_tssi_code - 512;
	else
		tssi->delta_tssi_txagc_offset[rf_path] = delta_tssi_code;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_code=0x%x(%d) delta_tssi_txagc_offset(%d) path=%d\n",
	       delta_tssi_code, delta_tssi_code,
	       tssi->delta_tssi_txagc_offset[rf_path], rf_path);

	tssi->delta_tssi_txagc_offset[rf_path] = tssi->delta_tssi_txagc_offset[rf_path] * small_a * 4;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) = delta_tssi_txagc_offset * small_a(%d) * 4 path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], small_a, rf_path);

	tssi->delta_tssi_txagc_offset[rf_path] = tssi->delta_tssi_txagc_offset[rf_path] / 1000;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) = delta_tssi_txagc_offset / 1000 path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], rf_path);

	tssi->tssi_trk_txagc_offset[rf_path] =
		tssi->tssi_trk_txagc_offset[rf_path] + tssi->delta_tssi_txagc_offset[rf_path];

	if (tssi->tssi_trk_txagc_offset[rf_path] > 63)
		tssi->tssi_trk_txagc_offset[rf_path] = 63;
	if (tssi->tssi_trk_txagc_offset[rf_path] < -64)
		tssi->tssi_trk_txagc_offset[rf_path] = -64;
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "tssi->tssi_trk_txagc_offset[i]=0x%x(%d) path=%d\n",
	       tssi->tssi_trk_txagc_offset[rf_path], tssi->tssi_trk_txagc_offset[rf_path], rf_path);

	odm_set_bb_reg(dm, txagc_offset[rf_path], 0x7f, (tssi->tssi_trk_txagc_offset[rf_path] & 0x7f));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) 0x%x[6:0]=0x%x path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], txagc_offset[rf_path],
	       odm_get_bb_reg(dm, txagc_offset[rf_path], 0x7f), rf_path);
	return 2;
}

void _halrf_get_tssi_normal_driver_result_8814b(
	void *dm_void,
	u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;

	u32 delta_tssi_code, i, j;
	u32 big_a, small_a, slope;
	/*s32 tssi_txagc_offset[4];*/
	s32 temp;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_result[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 txagc_offset[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};

	temp = odm_get_bb_reg(dm, tssi_result[rf_path], 0x10000);

	if (temp == 0) {
		tssi->tssi_finish_bit[rf_path] = 0;
		delta_tssi_code = 0;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"======>%s TSSI finish bit == 0, return path=%d !!!\n",
			__func__, rf_path);
		return;
	} else {
		tssi->tssi_finish_bit[rf_path] = 1;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "======>%s TSSI finish bit Ok path=%d !!!\n",
		       __func__, rf_path);
		
		delta_tssi_code = odm_get_bb_reg(dm, tssi_result[rf_path], 0x000001ff);
		odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x0);
	}

	big_a = odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, rf_path);
		rf->is_tssi_in_progress = 0;
		return;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a;			/* 1 * slope */

	if (delta_tssi_code & 0x100)
		tssi->delta_tssi_txagc_offset[rf_path] = delta_tssi_code - 512;
	else
		tssi->delta_tssi_txagc_offset[rf_path] = delta_tssi_code;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_code=0x%x(%d) delta_tssi_txagc_offset(%d) path=%d\n",
	       delta_tssi_code, delta_tssi_code,
	       tssi->delta_tssi_txagc_offset[rf_path], rf_path);

	tssi->delta_tssi_txagc_offset[rf_path] = tssi->delta_tssi_txagc_offset[rf_path] * small_a * 4;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) = delta_tssi_txagc_offset * small_a(%d) * 4 path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], small_a, rf_path);

	tssi->delta_tssi_txagc_offset[rf_path] = tssi->delta_tssi_txagc_offset[rf_path] / 1000;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) = delta_tssi_txagc_offset / 1000 path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], rf_path);

#if 0
	if (rf_path == RF_PATH_D) {
		for (i = 0; i < 4; i++)
			tssi_txagc_offset[i] = tssi->delta_tssi_txagc_offset[i];

		for (i = 0; i < 4; i++) {
			for (j = i; j < 4; j++) {
				if (tssi_txagc_offset[j] < tssi_txagc_offset[i]) {
					temp = tssi_txagc_offset[j];
					tssi_txagc_offset[j] = tssi_txagc_offset[i];
					tssi_txagc_offset[i] = temp;
				}
			}
		}
		
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"txagc_offset %d %d %d %d, tssi->delta_tssi_txagc_offset %d %d %d %d\n",
			tssi_txagc_offset[0], tssi_txagc_offset[1],
			tssi_txagc_offset[2], tssi_txagc_offset[3],
			tssi->delta_tssi_txagc_offset[0], tssi->delta_tssi_txagc_offset[1],
			tssi->delta_tssi_txagc_offset[2], tssi->delta_tssi_txagc_offset[3]);


		for (i = 0; i < 4; i++) {
			if ((tssi_txagc_offset[0] + 20) < tssi->delta_tssi_txagc_offset[i]) {
				tssi->delta_tssi_txagc_offset[i] = 0;
				tssi->tssi_trk_txagc_offset[i] = 0;
			}

			tssi->tssi_trk_txagc_offset[i] =
				tssi->tssi_trk_txagc_offset[i] + tssi->delta_tssi_txagc_offset[i];

			if (tssi->tssi_trk_txagc_offset[i] > 63)
				tssi->tssi_trk_txagc_offset[i] = 63;
			if (tssi->tssi_trk_txagc_offset[i] < -64)
				tssi->tssi_trk_txagc_offset[i] = -64;
			
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "tssi->tssi_trk_txagc_offset[i]=0x%x(%d) path=%d\n",
			       tssi->tssi_trk_txagc_offset[i], tssi->tssi_trk_txagc_offset[i], i);

			odm_set_bb_reg(dm, txagc_offset[i], 0x7f, (tssi->tssi_trk_txagc_offset[i] & 0x7f));

			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "delta_tssi_txagc_offset=0x%x(%d) 0x%x[6:0]=0x%x path=%d\n",
			       tssi->delta_tssi_txagc_offset[i],
			       tssi->delta_tssi_txagc_offset[i], txagc_offset[i],
			       odm_get_bb_reg(dm, txagc_offset[i], 0x7f), i);
		}
	}
#else

	tssi->tssi_trk_txagc_offset[rf_path] =
		tssi->tssi_trk_txagc_offset[rf_path] + tssi->delta_tssi_txagc_offset[rf_path];

	if (tssi->tssi_trk_txagc_offset[rf_path] > 63)
		tssi->tssi_trk_txagc_offset[rf_path] = 63;
	if (tssi->tssi_trk_txagc_offset[rf_path] < -64)
		tssi->tssi_trk_txagc_offset[rf_path] = -64;
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "tssi->tssi_trk_txagc_offset[%d]=0x%x(%d) path=%d\n",
	       rf_path, tssi->tssi_trk_txagc_offset[rf_path], tssi->tssi_trk_txagc_offset[rf_path], rf_path);

	odm_set_bb_reg(dm, txagc_offset[rf_path], 0x7f, (tssi->tssi_trk_txagc_offset[rf_path] & 0x7f));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_txagc_offset=0x%x(%d) 0x%x[6:0]=0x%x path=%d\n",
	       tssi->delta_tssi_txagc_offset[rf_path],
	       tssi->delta_tssi_txagc_offset[rf_path], txagc_offset[rf_path],
	       odm_get_bb_reg(dm, txagc_offset[rf_path], 0x7f), rf_path);

#endif
}


u8 halrf_do_tssi_8814b(
	void *dm_void,
	u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;

	u32 delta_tssi_code, i;
	u32 big_a, small_a, slope;
	s32 s_delta_tssi_code;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_setting[4] = {0x1830, 0x4130, 0x5230, 0x5330};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};
	u32 tssi_result[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 txagc_offset[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};

	rf->is_tssi_in_progress = 1;

	big_a = odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, rf_path);
		rf->is_tssi_in_progress = 0;
		return 0;
	}

	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a;			/* 1 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[rf_path], big_a_bit_mask[rf_path],
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       big_a, big_a_reg[rf_path], big_a_bit_mask[rf_path], rf_path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1*slope(%d) = 1000/small_a path=%d\n",
	       small_a, big_a, slope, rf_path);

	odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x700b8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x706f0044);
	} else {
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x701f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x702f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x704f0042);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x706f0042);
	}

	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x707b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x708b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x709b8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70ab8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70bb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70cb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70db8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70eb8041);
	odm_set_bb_reg(dm, tssi_setting[rf_path], MASKDWORD, 0x70fb8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x1);
	} else {
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
		odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x1);	
	}

	odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x0);
	odm_set_bb_reg(dm, tssi_trigger[rf_path], 0x10000000, 0x1);

	for (i = 0; odm_get_bb_reg(dm, tssi_result[rf_path], 0x10000) == 0; i++) {
		ODM_delay_ms(1);
		/*RF_DBG(dm, DBG_RF_TX_PWR_TRACK,*/
		/*	 "TSSI finish bit != 1 retry=%d path=%d   0x%x\n", i, rf_path,*/
		/*	 odm_get_bb_reg(dm, tssi_result[rf_path], MASKDWORD));*/
		if (i >= 300) {
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "TSSI finish bit i > 300ms, return path=%d\n", rf_path);
			/*_reload_bb_registers_8814b(dm, bb_reg, bb_reg_backup, 1);*/
			rf->is_tssi_in_progress = 0;
			return 1;
		}
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "TSSI finish bit Ok path=%d !!!\n", rf_path);
	
	delta_tssi_code = odm_get_bb_reg(dm, tssi_result[rf_path], 0x000001ff);

	if (delta_tssi_code & 0x100)
		s_delta_tssi_code = delta_tssi_code - 512;
	else
		s_delta_tssi_code = delta_tssi_code;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "delta_tssi_code=0x%x(%d) s_delta_tssi_code(%d) path=%d\n",
	       delta_tssi_code, delta_tssi_code, s_delta_tssi_code, rf_path);

	s_delta_tssi_code = s_delta_tssi_code * small_a * 4;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "s_delta_tssi_code=0x%x(%d) = s_delta_tssi_code * small_a(%d) * 4 path=%d\n",
	       s_delta_tssi_code, s_delta_tssi_code, small_a, rf_path);

	s_delta_tssi_code = s_delta_tssi_code / 1000;

	if (s_delta_tssi_code >= 0x3f)
		s_delta_tssi_code = 0;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "s_delta_tssi_code=0x%x(%d) = s_delta_tssi_code / 1000 path=%d\n",
	       s_delta_tssi_code, s_delta_tssi_code, rf_path);

	tssi->tssi_trk_txagc_offset[rf_path] = tssi->tssi_trk_txagc_offset[rf_path] + s_delta_tssi_code;

	if (tssi->tssi_trk_txagc_offset[rf_path] > 63)
		tssi->tssi_trk_txagc_offset[rf_path] = 63;
	if (tssi->tssi_trk_txagc_offset[rf_path] < -64)
		tssi->tssi_trk_txagc_offset[rf_path] = -64;
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "tssi->tssi_trk_txagc_offset[rf_path]=0x%x(%d) path=%d\n",
	       tssi->tssi_trk_txagc_offset[rf_path], tssi->tssi_trk_txagc_offset[rf_path], rf_path);

	odm_set_bb_reg(dm, txagc_offset[rf_path], 0x7f, (tssi->tssi_trk_txagc_offset[rf_path] & 0x7f));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "s_delta_tssi_code=0x%x(%d) 0x%x[6:0]=0x%x path=%d\n",
	       s_delta_tssi_code, s_delta_tssi_code, txagc_offset[rf_path],
	       odm_get_bb_reg(dm, txagc_offset[rf_path], 0x7f), rf_path);

	rf->is_tssi_in_progress = 0;
	return 2;

}

void halrf_do_get_tssi_8814b(
	void *dm_void,
	u8 rf_path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	if (rf->is_tssi_in_progress == 1)
		return;

	rf->is_tssi_in_progress = 1;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"%s tssi->thermal_trigger=%d\n", __func__, tssi->thermal_trigger);

	if (!tssi->thermal_trigger) {
		halrf_trigger_tssi_8814b(dm, rf_path);
	} else {
		_halrf_get_tssi_normal_driver_result_8814b(dm, rf_path);
	}

	rf->is_tssi_in_progress = 0;
}


void halrf_calculate_tssi_codeword_8814b(
	void *dm_void,
	u8 rf_path)
{

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	u8 i, rate;
	u8 channel = *dm->channel, bandwidth = *dm->band_width;
	u32 big_a, small_a, slope, db_temp;
	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	s32 small_b = 90;

	big_a = odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, rf_path);
		return;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000000 / small_a;			/* 1000 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[rf_path], big_a_bit_mask[rf_path],
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       odm_get_bb_reg(dm, big_a_reg[rf_path], big_a_bit_mask[rf_path]),
	       big_a, big_a_reg[rf_path], big_a_bit_mask[rf_path], rf_path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1000*slope(%d) = 1000000/small_a path=%d\n",
	       small_a, big_a, slope, rf_path);

	for (i = 0; i < TSSI_CODE_NUM; i++) {
		rate = _halrf_tssi_rate_to_driver_rate_8814b(dm, i);
		db_temp = (u32)phydm_get_tx_power_mdbm(dm, rf_path, rate, bandwidth, channel);
		db_temp = db_temp * slope;
		db_temp = db_temp / 100000 + small_b;
		tssi->tssi_codeword[i] = (u16)(db_temp);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "phydm_get_tx_power_mdbm = %d, rate=0x%x(%d) bandwidth=%d channel=%d rf_path=%d\n",
			phydm_get_tx_power_mdbm(dm, rf_path, rate, bandwidth, channel),
			rate, rate, bandwidth, channel, rf_path);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "tssi_codeword[%d] = 0x%x(%d)\n",
			i, tssi->tssi_codeword[i], tssi->tssi_codeword[i]);
	}
}

void halrf_set_tssi_codeword_8814b(
	void *dm_void, u16 *tssi_value)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i, j, k = 0, tssi_value_tmp;

	odm_set_bb_reg(dm, R_0x1c90, BIT(14), 0x0);

	/*power by rate table (tssi codeword)*/
	for (i = 0x3a54; i <= 0x3aa4; i = i + 4) {
		tssi_value_tmp = 0;

		for (j = 0; j < 31; j = j + 8)
			tssi_value_tmp = tssi_value_tmp | ((tssi_value[k++] & 0xff) << j);

		odm_set_bb_reg(dm, i, MASKDWORD, tssi_value_tmp);

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s write addr:0x%x value=0x%08x\n",
		       __func__, i, tssi_value_tmp);
	}

	odm_set_bb_reg(dm, R_0x1c90, BIT(14), 0x1);
}

u8 halrf_get_tssi_codeword_8814b(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 tssi_rate;

	tssi_rate = _halrf_driver_rate_to_tssi_rate_8814b(dm, ODM_MGN_MCS7);
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "Call:%s tssi_rate=%d tssi_codeword/2=0x%x\n",
		__func__, tssi_rate, (tssi->tssi_codeword[tssi_rate] / 2));
	
	return (u8)(tssi->tssi_codeword[tssi_rate] / 2);
}

u32 halrf_query_tssi_value_8814b(
	void *dm_void)
{
	s32 tssi_codeword = 0;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 tssi_rate;
	u8 rate = phydm_get_tx_rate(dm);

	tssi_rate = _halrf_driver_rate_to_tssi_rate_8814b(dm, rate);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s tx_rate=0x%x tssi_codeword=0x%x\n",
	       __func__, rate, tssi->tssi_codeword[tssi_rate]);

	return (u32)tssi->tssi_codeword[tssi_rate];
}

u32 halrf_set_tssi_value_8814b(
	void *dm_void, u32 tssi_codeowrd)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 tssi_rate;
	u8 rate = phydm_get_tx_rate(dm);

	u32 big_a, small_a, slope;
	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	s32 small_b = 90;
	u32 tssi_dbm;

	tssi_rate = _halrf_driver_rate_to_tssi_rate_8814b(dm, rate);
	tssi->tssi_codeword[tssi_rate] = (u16)tssi_codeowrd;
	halrf_set_tssi_codeword_8814b(dm, tssi->tssi_codeword);

	big_a = odm_get_bb_reg(dm, big_a_reg[RF_PATH_A], big_a_bit_mask[RF_PATH_A]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d rf_path=%d return !!!\n",
		       __func__, big_a, RF_PATH_A);
		return 0;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000000 / small_a;		/* 1000 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[RF_PATH_A], big_a_bit_mask[RF_PATH_A],
	       odm_get_bb_reg(dm, big_a_reg[RF_PATH_A], big_a_bit_mask[RF_PATH_A]),
	       odm_get_bb_reg(dm, big_a_reg[RF_PATH_A], big_a_bit_mask[RF_PATH_A]),
	       big_a, big_a_reg[RF_PATH_A], big_a_bit_mask[RF_PATH_A], RF_PATH_A);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1000*slope(%d) = 1000000/small_a path=%d\n",
	       small_a, big_a, slope, RF_PATH_A);


	if ((s32)tssi_codeowrd <= small_b)
		tssi_dbm = 0;
	else {
		tssi_dbm = (tssi_codeowrd - small_b) * 100000;
		tssi_dbm = tssi_dbm / slope;
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s tx_rate=0x%x tssi_codeowrd=%d 100*tssi_dbm=0x%x\n",
	       __func__, rate, tssi_codeowrd, tssi_dbm);

	return tssi_dbm;
}

void halrf_tssi_get_efuse_8814b(
	void *dm_void)
{

#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	struct rtl8192cd_priv *priv = dm->priv;
	u8 i;
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "=====>%s\n", __func__);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_A:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_A[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_B:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_B[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_C:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_C[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_D:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSICCK_D[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_A:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_A[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_B:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_B[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_C:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_C[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_D:\n");
	for (i = 0; i < MAX_2G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_D[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");
	
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_A:\n");
	for (i = 0; i < MAX_5G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_A[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_B:\n");
	for (i = 0; i < MAX_5G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_B[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_C:\n");
	for (i = 0; i < MAX_5G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_C[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_D:\n");
	for (i = 0; i < MAX_5G_CHANNEL_NUM; i++)
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "0x%x ", priv->pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_D[i]);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "\n");

	_halrf_driver_flash_to_tssi_de_8814b(dm);

#else
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	u8 pg = 0xff, i, j;
	u32 pg_tmp;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "===>%s\n", __func__);

	/*path s0*/
	j = 0;
	for (i = 0x10; i <= 0x1a; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[0][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 0, j, tssi->tssi_efuse[0][j]);
		j++;
	}

	for (i = 0x22; i <= 0x2f; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[0][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 0, j, tssi->tssi_efuse[0][j]);
		j++;
	}

	/*path s1*/
	j = 0;
	for (i = 0x3a; i <= 0x44; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[1][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 1, j, tssi->tssi_efuse[1][j]);
		j++;
	}

	for (i = 0x4c; i <= 0x59; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[1][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 1, j, tssi->tssi_efuse[1][j]);
		j++;
	}

	/*path s2*/
	j = 0;
	for (i = 0x64; i <= 0x6e; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[2][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 2, j, tssi->tssi_efuse[2][j]);
		j++;
	}

	for (i = 0x76; i <= 0x83; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[2][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 2, j, tssi->tssi_efuse[2][j]);
		j++;
	}

	/*path s3*/
	j = 0;
	for (i = 0x8e; i <= 0x98; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[3][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 3, j, tssi->tssi_efuse[3][j]);
		j++;
	}

	for (i = 0xa0; i <= 0xad; i++) {
		odm_efuse_logical_map_read(dm, 1, i, &pg_tmp);
		tssi->tssi_efuse[3][j] = (s8)pg_tmp;
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"tssi->tssi_efuse[%d][%d]=%d\n", 3, j, tssi->tssi_efuse[3][j]);
		j++;
	}
#endif

}

void halrf_get_efuse_thermal_pwrtype_8814b(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &(dm->rf_calibrate_info);
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	u32 thermal_tmp, pg_tmp;

	tssi->thermal[RF_PATH_A] = 0xff;
	tssi->thermal[RF_PATH_B] = 0xff;
	tssi->thermal[RF_PATH_C] = 0xff;
	tssi->thermal[RF_PATH_D] = 0xff;

	/*path s0*/
	odm_efuse_logical_map_read(dm, 1, 0xd0, &thermal_tmp);
	tssi->thermal[RF_PATH_A] = (u8)thermal_tmp;

	/*path s1*/
	odm_efuse_logical_map_read(dm, 1, 0xd1, &thermal_tmp);
	tssi->thermal[RF_PATH_B] = (u8)thermal_tmp;

	/*path s2*/
	odm_efuse_logical_map_read(dm, 1, 0xd2, &thermal_tmp);
	tssi->thermal[RF_PATH_C] = (u8)thermal_tmp;

	/*path s3*/
	odm_efuse_logical_map_read(dm, 1, 0xd3, &thermal_tmp);
	tssi->thermal[RF_PATH_D] = (u8)thermal_tmp;

	/*power tracking type*/
	odm_efuse_logical_map_read(dm, 1, 0xc8, &pg_tmp);
	rf->power_track_type = (u8)((pg_tmp >> 4) & 0xf);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s thermal pahtA=0x%x pahtB=0x%x pahtC=0x%x pahtD=0x%x power_track_type=0x%x\n",
	       __func__, tssi->thermal[RF_PATH_A],  tssi->thermal[RF_PATH_B],
	       tssi->thermal[RF_PATH_C],  tssi->thermal[RF_PATH_D],
	       rf->power_track_type);
	
}


void halrf_tssi_set_de_8814b(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 i;
	u32 addr_d[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 addr_d_bitmask[4] = {0xff000000, 0x3fc00000, 0x3fc00000, 0x3fc00000};
	u32 addr_cck_d[4] = {0x18e8, 0x1ef0, 0x1ef8, 0x1eb8};
	u32 addr_cck_d_bitmask[4] = {0x01fe0000, 0x0001fe00, 0x0001fe00, 0x7f800000};
	u32 tssi_offest_de, offset_index = 0;
	u8 channel = *dm->channel;

	if (dm->rf_calibrate_info.txpowertrack_control == 4) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"==>%s txpowertrack_control=%d return!!!\n", __func__,
			dm->rf_calibrate_info.txpowertrack_control);

		for (i = 0; i < MAX_PATH_NUM_8814B; i++) {
			odm_set_bb_reg(dm, addr_cck_d[i], addr_cck_d_bitmask[i], 0x0);
			odm_set_bb_reg(dm, addr_d[i], addr_d_bitmask[i], 0x0);
		}
		return;
	}

#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	if (channel >= 1 && channel <= 3)	/*AP 2G CCK*/
		offset_index = 0;
	else if (channel >= 3 && channel <= 5)
		offset_index = 1;
	else if (channel >= 6 && channel <= 8)
		offset_index = 2;
	else if (channel >= 9 && channel <= 11)
		offset_index = 3;
	else if (channel >= 12 && channel <= 14)
		offset_index = 4;
#else
	if (channel >= 1 && channel <= 2)	/*Windows/CE 2G CCK*/
		offset_index = 0;
	else if (channel >= 3 && channel <= 5)
		offset_index = 1;
	else if (channel >= 6 && channel <= 8)
		offset_index = 2;
	else if (channel >= 9 && channel <= 11)
		offset_index = 3;
	else if (channel >= 12 && channel <= 13)
		offset_index = 4;
	else if (channel == 14)
		offset_index = 5;
#endif

	for (i = 0; i < MAX_PATH_NUM_8814B; i++) {
		odm_set_bb_reg(dm, addr_cck_d[i], addr_cck_d_bitmask[i],
			(tssi->tssi_efuse[i][offset_index] & 0xff));
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"==>%s CCK 0x%x[%x] tssi_efuse_offset=%d\n", __func__,
			addr_cck_d[i], addr_cck_d_bitmask[i], tssi->tssi_efuse[i][offset_index]);

		tssi_offest_de = _halrf_get_efuse_tssi_offset_8814b(dm, i);
		odm_set_bb_reg(dm, addr_d[i], addr_d_bitmask[i], (tssi_offest_de & 0xff));
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			"==>%s OFDM 0x%x[%x] tssi_efuse_offset=%d\n", __func__,
			addr_d[i], addr_d_bitmask[i], tssi_offest_de);
	}
}

void halrf_tssi_set_de_for_tx_verify_8814b(
	void *dm_void, u32 tssi_de, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	u32 addr_d[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 addr_d_bitmask[4] = {0xff000000, 0x3fc00000, 0x3fc00000, 0x3fc00000};
	u32 addr_cck_d[4] = {0x18e8, 0x1ef0, 0x1ef8, 0x1eb8};
	u32 addr_cck_d_bitmask[4] = {0x01fe0000, 0x0001fe00, 0x0001fe00, 0x7f800000};

	odm_set_bb_reg(dm, addr_cck_d[path], addr_cck_d_bitmask[path], (tssi_de & 0xff));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"==>%s CCK 0x%x[%x] tssi_de=%d path=%d\n", __func__,
		addr_cck_d[path], addr_cck_d_bitmask[path], tssi_de, path);

	odm_set_bb_reg(dm, addr_d[path], addr_d_bitmask[path], (tssi_de & 0xff));

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"==>%s OFDM 0x%x[%x] tssi_de=%d path=%d\n", __func__,
		addr_d[path], addr_d_bitmask[path], tssi_de, path);
}

void halrf_tssi_clean_de_8814b(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;

	rf->is_tssi_in_progress = 1;

	/*path s0*/
	odm_set_bb_reg(dm, R_0x18a4, 0x10000000, 0x0);

	/*path s1*/
	odm_set_bb_reg(dm, R_0x41a4, 0x10000000, 0x0);

	/*path s2*/
	odm_set_bb_reg(dm, R_0x52a4, 0x10000000, 0x0);

	/*path s3*/
	odm_set_bb_reg(dm, R_0x53a4, 0x10000000, 0x0);

	ODM_delay_ms(10);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		"======>%s 0x28a4=0x%x 0x45a4=0x%x 0x56a4=0x%x 0x57a4=0x%x\n",
		__func__,
		odm_get_bb_reg(dm, R_0x28a4, MASKDWORD),
		odm_get_bb_reg(dm, R_0x45a4, MASKDWORD),
		odm_get_bb_reg(dm, 0x56a4, MASKDWORD),
		odm_get_bb_reg(dm, 0x57a4, MASKDWORD));

	rf->is_tssi_in_progress = 0;
}

u32 halrf_tssi_trigger_de_8814b(
	void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;

	u32 delta_tssi_code, i;
	u32 big_a, small_a, slope;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_setting[4] = {0x1830, 0x4130, 0x5230, 0x5330};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};
	u32 tssi_result[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 txagc_offset[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};

	u32 tssi_offest_de = 0;

	rf->is_tssi_in_progress = 1;

	big_a = odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d path=%d return !!!\n",
		       __func__, big_a, path);
		rf->is_tssi_in_progress = 0;
		return 0;
	}

	if (odm_get_bb_reg(dm, tssi_result[path], 0xffffffff) != 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s tssi_result != 0 path=%d return !!!\n",
		       __func__, path);
		rf->is_tssi_in_progress = 0;
		return 0;
	}
	
	big_a = (big_a * 100000) / 128; 	/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a; 		/* 1 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[path], big_a_bit_mask[path],
	       odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]),
	       odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]),
	       big_a, big_a_reg[path], big_a_bit_mask[path], path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1*slope(%d) = 1000/small_a path=%d\n",
	       small_a, big_a, slope, path);

	odm_set_bb_reg(dm, tssi_trigger[path], 0xe0000000, 0x5);

	odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x700b8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x706f0044);
	} else {
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x701f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x702f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x704f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x706f0042);
	}

	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x707b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x708b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x709b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70ab8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70bb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70cb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70db8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70eb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70fb8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00100, 0x0);
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00002, 0x1);
	} else {
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00002, 0x0);
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00100, 0x1);	
	}

	odm_set_bb_reg(dm, tssi_trigger[path], 0x10000000, 0x0);
	odm_set_bb_reg(dm, tssi_trigger[path], 0x10000000, 0x1);

	rf->is_tssi_in_progress = 0;
	return 1;
}


u32 halrf_tssi_get_de_8814b(
	void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;
	u8 channel = *dm->channel;

	u32 delta_tssi_code, i;
	u32 big_a, small_a, slope;

	u32 big_a_reg[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 big_a_bit_mask[4] = {0x7ffc, 0x1fff, 0x1fff, 0x1fff};
	u32 tssi_setting[4] = {0x1830, 0x4130, 0x5230, 0x5330};
	u32 tssi_trigger[4] = {0x18a4, 0x41a4, 0x52a4, 0x53a4};
	u32 tssi_result[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 txagc_offset[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};

	u32 tssi_offest_de = 0;

	rf->is_tssi_in_progress = 1;

	big_a = odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]);

	if (big_a == 0) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
		       "===>%s big_a = %d path=%d return !!!\n",
		       __func__, big_a, path);
		odm_set_bb_reg(dm, tssi_trigger[path], 0xe0000000, 0x0);
		rf->is_tssi_in_progress = 0;
		return 0;
	}
	
	big_a = (big_a * 100000) / 128;		/* 100000 * big_a */
	small_a = 651441723 / big_a;		/* 1000 * small_a */
	slope = 1000 / small_a;			/* 1 * slope */

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "===>%s 0x%x[%x] = 0x%x(%d) 100000*big_a(%d) = 0x%x[%x] / 128 path=%d\n",
	       __func__, big_a_reg[path], big_a_bit_mask[path],
	       odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]),
	       odm_get_bb_reg(dm, big_a_reg[path], big_a_bit_mask[path]),
	       big_a, big_a_reg[path], big_a_bit_mask[path], path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "1000 * small_a(%d) = 651441723 / big_a(%d)  1*slope(%d) = 1000/small_a path=%d\n",
	       small_a, big_a, slope, path);

#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)

	odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x700b8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x701f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x702f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x704f0044);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x706f0044);
	} else {
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x701f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x702f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x703f0041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x704f0042);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x706f0042);
	}

	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x707b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x708b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x709b8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70ab8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70bb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70cb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70db8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70eb8041);
	odm_set_bb_reg(dm, tssi_setting[path], MASKDWORD, 0x70fb8041);

	if (channel >= 1 && channel <= 14) {
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00100, 0x0);
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00002, 0x1);
	} else {
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00002, 0x0);
		odm_set_rf_reg(dm, path, RF_0x7f, 0x00100, 0x1);	
	}

	odm_set_bb_reg(dm, tssi_trigger[path], 0x10000000, 0x0);
	odm_set_bb_reg(dm, tssi_trigger[path], 0x10000000, 0x1);

#endif	/*#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)*/

	for (i = 0; odm_get_bb_reg(dm, tssi_result[path], 0x10000) == 0; i++) {
		ODM_delay_ms(1);

		/*RF_DBG(dm, DBG_RF_TX_PWR_TRACK,*/
		/*	 "TSSI finish bit != 1 retry=%d path=%d   0x%x\n", i, path,*/
		/*	 odm_get_bb_reg(dm, tssi_result[path], MASKDWORD));*/
		if (i >= 300) {
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "TSSI finish bit i > 300ms, return path=%d\n", path);
			odm_set_bb_reg(dm, tssi_trigger[path], 0xe0000000, 0x0);
			rf->is_tssi_in_progress = 0;
			return 0;
		}
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "TSSI finish bit Ok path=%d !!!\n", path);
	
	tssi_offest_de = odm_get_bb_reg(dm, tssi_result[path], 0x000001ff);

	if (tssi_offest_de & BIT(8))
		tssi_offest_de = (tssi_offest_de & 0xff) | BIT(7);

	odm_set_bb_reg(dm, tssi_trigger[path], 0xe0000000, 0x0);

	rf->is_tssi_in_progress = 0;

	return tssi_offest_de;
}

void halrf_tssi_dck_8814b(
	void *dm_void, u8 direct_do)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	u8 channel = *dm->channel, bandwidth = *dm->band_width;
	u32 tmp;
	u8 i, j, k, retry_time = 6;

	u32 bb_reg[12] = {R_0x1c3c, R_0x2dbc, R_0x820, R_0x1e2c, R_0x1e28,
			R_0x1800, R_0x4100, R_0x5200, R_0x5300, R_0x1b00,
			R_0x1bcc, R_0x1d08};
	u32 bb_reg_backup[12] = {0};
	u32 backup_num = 12;

	u32 tssi_setting[4] = {R_0x1830, R_0x4130, R_0x5230, R_0x5330};
	u32 reg_1c3c_setting1[4] = {0x880, 0xa80, 0xc80, 0xe80};
	/*u32 reg_1c3c_setting2[4] = {0x937, 0xb37, 0xd37, 0xf37};*/
	u32 tssi_switch[4] = {R_0x18a4, R_0x41a4, R_0x52a4, R_0x53a4};
	u32 dck_offset[4] = {R_0x18a8, R_0x1eec, R_0x1ef4, R_0x1efc};
	u32 dck_cck_offset[4] = {R_0x1880, R_0x4180, R_0x5280, R_0x5380};
	u32 dck_offset_mask[4] = {0x00ff8000, 0x003fe000, 0x003fe000, 0x003fe000};
	u32 dck_check;
	u32 dck_level_check[4] = {0x932, 0xb32, 0xd32, 0xf32};
	u32 path_reg[4] = {R_0x1800, R_0x4100, R_0x5200, R_0x5300};
	u32 reg_820_setting[4] = {0xfff1, 0xfff2, 0xfff4, 0xfff8};
	u32 reg_1c28_setting[4] = {0x1, 0x2, 0x4, 0x8};
	u32 debug[4] = {0x28a4, 0x45a4, 0x56a4, 0x57a4};
	u32 debug1[4] = {0x28a0, 0x45a0, 0x56a0, 0x57a0};

	u32 addr_d[4] = {0x18a8, 0x1eec, 0x1ef4, 0x1efc};
	u32 addr_d_bitmask[4] = {0xff000000, 0x3fc00000, 0x3fc00000, 0x3fc00000};
	u32 addr_cck_d[4] = {0x18e8, 0x1ef0, 0x1ef8, 0x1eb8};
	u32 addr_cck_d_bitmask[4] = {0x01fe0000, 0x0001fe00, 0x0001fe00, 0x7f800000};

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] ======>%s channel=%d bandwidth=%d\n",
		__func__, channel, bandwidth);

	if (direct_do == false && *dm->band_type == rf->pre_band_type) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] direct_do=%d *dm->band_type(%d)==rf->pre_band_type(%d)\n",
			direct_do, *dm->band_type, rf->pre_band_type);
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] band is the same return!!!\n");
		return;
	}

	rf->is_tssi_in_progress = 1;

	_backup_bb_registers_8814b(dm, bb_reg, bb_reg_backup, backup_num);

	for (i = 0; i < MAX_PATH_NUM_8814B; i++) {
		odm_set_bb_reg(dm, addr_cck_d[i], addr_cck_d_bitmask[i], 0x0);
		odm_set_bb_reg(dm, addr_d[i], addr_d_bitmask[i], 0x0);
	}

	/*odm_set_bb_reg(dm, R_0x1834, BIT(15), 0x1);*/
	/*odm_set_bb_reg(dm, R_0x4134, BIT(15), 0x1);*/
	/*odm_set_bb_reg(dm, R_0x5234, BIT(15), 0x1);*/
	/*odm_set_bb_reg(dm, R_0x5334, BIT(15), 0x1);*/

	for (i = RF_PATH_A; i < MAX_PATH_NUM_8814B; i++) {

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] ===============Start path=%d ===============\n", i);

		if (channel >= 1 && channel <= 14) {
			rf->pre_band_type = ODM_BAND_2_4G;
			for (k = 0; k < retry_time; k++) {
				odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);

				/*CCA*/
				odm_set_bb_reg(dm, R_0x1d58, 0x00000008, 0x1);
				odm_set_bb_reg(dm, R_0x1d58, 0x00000ff0, 0xff);
				odm_set_bb_reg(dm, R_0x1a00, 0x00000003, 0x2);

				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x700b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x701f0044);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x702f0044);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x703f0041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x704f0044);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x705b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x706f0044);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x707b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x708b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x709b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70ab8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70bb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70cb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70db8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70eb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70fb8041);
				odm_set_rf_reg(dm, i, RF_0x7f, 0x00002, 0x1);

				odm_set_bb_reg(dm, R_0x820, 0x0000ffff, reg_820_setting[i]);
				odm_set_bb_reg(dm, R_0x1e2c, MASKDWORD, 0xe4e4e400);
				odm_set_bb_reg(dm, R_0x1e28, 0x0000000f, reg_1c28_setting[i]);
				odm_set_bb_reg(dm, path_reg[i], 0x000fffff, 0x33312);

				odm_set_bb_reg(dm, R_0x1d08, 0x00000001, 0x1);
				odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x1);
				odm_set_bb_reg(dm, R_0x1b00, 0x00000006, i);
				odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x3f);
				odm_set_rf_reg(dm, i, RF_0xde, 0x10000, 0x1);
				odm_set_rf_reg(dm, i, RF_0x56, 0x00fff, 0xe00);
				odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x1);
				ODM_delay_us(300);

				/*odm_set_bb_reg(dm, R_0x1c3c, 0x000fff00, reg_1c3c_setting1[i]);*/
				phydm_set_bb_dbg_port(dm, DBGPORT_PRI_2, reg_1c3c_setting1[i]);
				/*tmp = odm_get_bb_reg(dm, R_0x2dbc, 0x00fff000);*/
				tmp = (phydm_get_bb_dbg_port_val(dm) & 0x00fff000) >> 12;
				phydm_release_bb_dbg_port(dm);

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[23:12]=0x%x path=%d\n",
					tmp, i);

				tmp = tmp / 8;
				if (tmp <= 1)
					tmp = 0;
				else
					tmp = tmp - 1;
				odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);
				if (dm->cut_version >= ODM_CUT_C)
					odm_set_bb_reg(dm, dck_cck_offset[i], 0x7fc00000, tmp);

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x%x[%x]=0x%x path=%d\n",
					dck_offset[i], dck_offset_mask[i],
					odm_get_bb_reg(dm, dck_offset[i], dck_offset_mask[i]), i);

				for (j = 0; j < 3; j++) {
					odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x0);
					odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x1);
					odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);
					odm_set_bb_reg(dm, R_0x1e70, 0x00000002, 0x1);
					ODM_delay_us(300);
					odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x0);
					ODM_delay_us(300);
					/*odm_set_bb_reg(dm, R_0x1e70, 0x00000002, 0x0);*/
					odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x1);
					/*odm_set_bb_reg(dm, R_0x1c3c, 0xfff00, dck_level_check[i]);*/
					phydm_set_bb_dbg_port(dm, DBGPORT_PRI_2, dck_level_check[i]);

					ODM_delay_us(300);
					
					RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x%x=0x%x 0x%x=0x%x path=%d\n",
						debug[i], odm_get_bb_reg(dm, debug[i], MASKDWORD),
						debug1[i], odm_get_bb_reg(dm, debug1[i], MASKDWORD),
						i);
		
					/*dck_check = odm_get_bb_reg(dm, R_0x2dbc, 0x000003ff);*/
					dck_check = (phydm_get_bb_dbg_port_val(dm) & 0x000003ff);
					phydm_release_bb_dbg_port(dm);
			 
					if ((s32)dck_check < 0x0) {
						tmp = 0;

						odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);
						if (dm->cut_version >= ODM_CUT_C)
							odm_set_bb_reg(dm, dck_cck_offset[i], 0x7fc00000, tmp);
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x < 0x0 Set 0x%x  path=%d retry=%d\n",
							dck_check, tmp, i, j);
					} else if (dck_check > 0x4) {
						if (tmp >= 511)
							tmp = 512;
						else
							tmp = tmp + 1;
						odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);
						if (dm->cut_version >= ODM_CUT_C)
							odm_set_bb_reg(dm, dck_cck_offset[i], 0x7fc00000, tmp);
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x > 0x4 Set 0x%x path=%d retry=%d\n",
							dck_check, tmp, i, j);
					} else {
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x OK!!! path=%d retry=%d\n",
							dck_check, i, j);
						k = retry_time;
						break;
					}
				}
			}

			odm_set_bb_reg(dm, R_0x1b00, 0x00000006, i);
			odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x0);
			odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x0);
			odm_set_rf_reg(dm, i, RF_0x7f, 0x00002, 0x0);
			odm_set_bb_reg(dm, R_0x1e70, 0x00000002, 0x0);
			odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);
			odm_set_rf_reg(dm, i, RF_0xde, 0x10000, 0x0);
			odm_set_bb_reg(dm, R_0x1d08, 0x00000001, 0x0);

			odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x0);

			/*CCA*/
			odm_set_bb_reg(dm, R_0x1d58, 0x00000008, 0x0);
			odm_set_bb_reg(dm, R_0x1d58, 0x00000ff0, 0x0);
			odm_set_bb_reg(dm, R_0x1a00, 0x00000003, 0x0);
		} else {
			rf->pre_band_type = ODM_BAND_5G;

			for (k = 0; k < retry_time; k++) {
				odm_set_bb_reg(dm, R_0x1c38, MASKDWORD, 0xf7d5005e);

				/*CCA*/
				odm_set_bb_reg(dm, R_0x1d58, 0x00000008, 0x1);
				odm_set_bb_reg(dm, R_0x1d58, 0x00000ff0, 0xff);
				odm_set_bb_reg(dm, R_0x1a00, 0x00000003, 0x2);

				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x700b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x701f0042);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x702f0042);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x703f0041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x704f0042);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x705b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x706f0042);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x707b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x708b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x709b8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70ab8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70bb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70cb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70db8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70eb8041);
				odm_set_bb_reg(dm, tssi_setting[i], MASKDWORD, 0x70fb8041);
				odm_set_rf_reg(dm, i, RF_0x7f, 0x00100, 0x1);

				odm_set_bb_reg(dm, R_0x820, 0x0000ffff, reg_820_setting[i]);
				odm_set_bb_reg(dm, R_0x1e2c, MASKDWORD, 0xe4e4e400);
				odm_set_bb_reg(dm, R_0x1e28, 0x0000000f, reg_1c28_setting[i]);
				odm_set_bb_reg(dm, path_reg[i], 0x000fffff, 0x33312);

				odm_set_bb_reg(dm, R_0x1d08, 0x00000001, 0x1);
				odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x1);
				odm_set_bb_reg(dm, R_0x1b00, 0x00000006, i);
				odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x3f);
				odm_set_rf_reg(dm, i, RF_0xde, 0x10000, 0x1);
				odm_set_rf_reg(dm, i, RF_0x56, 0x00fff, 0xc00);

				/*Set OFDM Packet Type*/
				odm_set_bb_reg(dm, R_0x900, 0x00000004, 0x1);
				odm_set_bb_reg(dm, R_0x900, 0x30000000, 0x2);
				odm_set_bb_reg(dm, R_0x908, 0x00ffffff, 0x2014b);
				odm_set_bb_reg(dm, R_0x90c, 0x00ffffff, 0x800006);
				odm_set_bb_reg(dm, R_0x910, 0x00ffffff, 0x13600);
				odm_set_bb_reg(dm, R_0x914, 0x1fffffff, 0x6000fa);
				odm_set_bb_reg(dm, R_0x938, 0x0000ffff, 0x4b0f);
				odm_set_bb_reg(dm, R_0x940, MASKDWORD, 0x4ee33e41);
				odm_set_bb_reg(dm, R_0xa58, 0x003f8000, 0x2c);

				odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x1);
				odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);
				ODM_delay_us(300);
				
				
				/*odm_set_bb_reg(dm, R_0x1c3c, 0x000fff00, reg_1c3c_setting1[i]);*/
				phydm_set_bb_dbg_port(dm, DBGPORT_PRI_2, reg_1c3c_setting1[i]);
				/*tmp = odm_get_bb_reg(dm, R_0x2dbc, 0x00fff000);*/
				tmp = (phydm_get_bb_dbg_port_val(dm) & 0x00fff000) >> 12;
				phydm_release_bb_dbg_port(dm);

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[23:12]=0x%x path=%d\n",
					tmp, i);

				odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x0);
				ODM_delay_us(300);

				tmp = tmp / 8;
				if (tmp <= 1)
					tmp = 0;
				else
					tmp = tmp - 2;
				odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x%x[%x]=0x%x path=%d\n",
					dck_offset[i], dck_offset_mask[i],
					odm_get_bb_reg(dm, dck_offset[i], dck_offset_mask[i]), i);

				for (j = 0; j < 3; j++) {
					odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x0);
					odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x1);
					/*odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);*/
					odm_set_bb_reg(dm, R_0x1e70, 0x00000002, 0x1);
					ODM_delay_us(300);
					/*odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x0);*/
					/*ODM_delay_us(300);*/
					/*odm_set_bb_reg(dm, R_0x1e70, 0x00000002, 0x0);*/
					odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x1);
					odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);
					/*odm_set_bb_reg(dm, R_0x1c3c, 0xfff00, dck_level_check[i]);*/
					phydm_set_bb_dbg_port(dm, DBGPORT_PRI_2, dck_level_check[i]);

					ODM_delay_us(300);
					/*dck_check = odm_get_bb_reg(dm, R_0x2dbc, 0x000003ff);*/
					dck_check = (phydm_get_bb_dbg_port_val(dm) & 0x000003ff);
					phydm_release_bb_dbg_port(dm);

					if (dck_check < 0x3) {
						if (tmp <= 1)
							tmp = 0;
						else
							tmp = tmp - 1;
						odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x < 0x3 Set 0x%x  path=%d retry=%d\n",
							dck_check, tmp, i, j);
					} else if (dck_check > 0x7) {
						if (tmp >= 511)
							tmp = 512;
						else
							tmp = tmp + 1;
						odm_set_bb_reg(dm, dck_offset[i], dck_offset_mask[i], tmp);
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x > 0x6 Set 0x%x path=%d retry=%d\n",
							dck_check, tmp, i, j);
					} else {
						RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] 0x2dbc[9:0]=0x%x OK!!! path=%d retry=%d\n",
							dck_check, i, j);
						k = retry_time;
						break;
					}
				}
			}

			odm_set_bb_reg(dm, R_0x1b00, 0x00000006, i);
			odm_set_bb_reg(dm, R_0x1bcc, 0x0000003f, 0x0);
			odm_set_bb_reg(dm, R_0x1ca4, 0x00000001, 0x0);
			odm_set_rf_reg(dm, i, RF_0x7f, 0x00100, 0x0);
			odm_set_bb_reg(dm, R_0x1e70, 0x00000004, 0x0);
			odm_set_rf_reg(dm, i, RF_0xde, 0x10000, 0x0);
			odm_set_bb_reg(dm, R_0x1d08, 0x00000001, 0x0);

			odm_set_bb_reg(dm, tssi_switch[i], 0x10000000, 0x0);

			/*CCA*/
			odm_set_bb_reg(dm, R_0x1d58, 0x00000008, 0x0);
			odm_set_bb_reg(dm, R_0x1d58, 0x00000ff0, 0x0);
			odm_set_bb_reg(dm, R_0x1a00, 0x00000003, 0x0);
		}

		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "[TSSI][DCK] ===============End path=%d ===============\n", i);
	}
	_reload_bb_registers_8814b(dm, bb_reg, bb_reg_backup, backup_num);
	rf->is_tssi_in_progress = 0;
}



void odm_pwrtrack_method_set_pwr8814b(void *dm_void,
				      enum pwrtrack_method method,
				      u8 rf_path, u8 tx_pwr_idx_offset)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_tssi_data *tssi = &rf->halrf_tssi_data;

	u8 bb_swing_idx_ofdm = 0;
	u32 bitmask_6_0 = BIT(6) | BIT(5) | BIT(4) | BIT(3) |
			BIT(2) | BIT(1) | BIT(0);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "===> %s method=%d\n", __func__, method);

	/*use for mp driver clean power tracking status*/
	if (method == CLEAN_MODE) { /*use for mp driver clean power tracking status*/
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "===> %s method=%d clear power tracking rf_path=%d\n",
		       __func__, method, rf_path);
		tssi->tssi_trk_txagc_offset[rf_path] = 0;

		switch (rf_path) {
		case RF_PATH_A:
			odm_set_bb_reg(dm, R_0x18a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x18a0,
			       odm_get_bb_reg(dm, R_0x18a0, bitmask_6_0));
			break;
		case RF_PATH_B:
			odm_set_bb_reg(dm, R_0x41a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x41a0,
			       odm_get_bb_reg(dm, R_0x41a0, bitmask_6_0));
			break;
		case RF_PATH_C:
			odm_set_bb_reg(dm, R_0x52a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x52a0,
			       odm_get_bb_reg(dm, R_0x52a0, bitmask_6_0));
			break;
		case RF_PATH_D:
			odm_set_bb_reg(dm, R_0x53a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00002, 0x0);
			odm_set_rf_reg(dm, rf_path, RF_0x7f, 0x00100, 0x0);
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x\n", rf_path, R_0x53a0,
			       odm_get_bb_reg(dm, R_0x53a0, bitmask_6_0));
			break;
		default:
			break;
		}
	} else if (method == MIX_MODE) {
		RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "===> %s method=%d MIX_MODE power tracking rf_path=%d\n",
		       __func__, method, rf_path);

		switch (rf_path) {
		case RF_PATH_A:
			odm_set_bb_reg(dm, R_0x18a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x(%d)\n", rf_path, R_0x18a0,
			       odm_get_bb_reg(dm, R_0x18a0, bitmask_6_0),
			       odm_get_bb_reg(dm, R_0x18a0, bitmask_6_0));
			break;
		case RF_PATH_B:
			odm_set_bb_reg(dm, R_0x41a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x(%d)\n", rf_path, R_0x41a0,
			       odm_get_bb_reg(dm, R_0x41a0, bitmask_6_0),
			       odm_get_bb_reg(dm, R_0x41a0, bitmask_6_0));
			break;
		case RF_PATH_C:
			odm_set_bb_reg(dm, R_0x52a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x(%d)\n", rf_path, R_0x52a0,
			       odm_get_bb_reg(dm, R_0x52a0, bitmask_6_0),
			       odm_get_bb_reg(dm, R_0x52a0, bitmask_6_0));
			break;
		case RF_PATH_D:
			odm_set_bb_reg(dm, R_0x53a0, bitmask_6_0, (cali_info->absolute_ofdm_swing_idx[rf_path] & 0x7f));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "Path-%d 0x%x=0x%x(%d)\n", rf_path, R_0x53a0,
			       odm_get_bb_reg(dm, R_0x53a0, bitmask_6_0),
			       odm_get_bb_reg(dm, R_0x53a0, bitmask_6_0));
			break;
		default:
			break;
		}
	} else if (method == TSSI_MODE) {
		halrf_do_get_tssi_8814b(dm, rf_path);
		_halrf_tssi_set_de_by_thermal_8814b(dm, rf_path);
	}
}

void odm_tx_pwr_track_set_pwr8814b(void *dm_void, enum pwrtrack_method method,
				   u8 rf_path, u8 channel_mapped_index)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	u8 tx_pwr_idx_offset = 0;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->default_ofdm_index=%d   pRF->default_cck_index=%d\n",
	       cali_info->default_ofdm_index, cali_info->default_cck_index);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "absolute_ofdm_swing_idx=%d remnant_ofdm_swing_idx=%d path=%d\n",
	       cali_info->absolute_ofdm_swing_idx[rf_path],
	       cali_info->remnant_ofdm_swing_idx[rf_path], rf_path);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "absolute_cck_swing_idx=%d remnant_cck_swing_idx=%d path=%d\n",
	       cali_info->absolute_cck_swing_idx[rf_path],
	       cali_info->remnant_cck_swing_idx, rf_path);

	odm_pwrtrack_method_set_pwr8814b(dm, method, rf_path,
					 tx_pwr_idx_offset);
}

void get_delta_swing_table_8814b(void *dm_void,
				 u8 **temperature_up_a,
				 u8 **temperature_down_a,
				 u8 **temperature_up_b,
				 u8 **temperature_down_b)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	u8 channel = *dm->channel;
	u8 tx_rate = phydm_get_tx_rate(dm);

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

	if (channel >= 36 && channel <= 64) {
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

void get_delta_swing_table_8814b_path_cd(void *dm_void,
				 u8 **temperature_up_c,
				 u8 **temperature_down_c,
				 u8 **temperature_up_d,
				 u8 **temperature_down_d)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	u8 channel = *dm->channel;
	u8 tx_rate = phydm_get_tx_rate(dm);

	if (channel >= 1 && channel <= 14) {
		if (IS_CCK_RATE(tx_rate)) {
			*temperature_up_c = cali_info->delta_swing_table_idx_2g_cck_c_p;
			*temperature_down_c = cali_info->delta_swing_table_idx_2g_cck_c_n;
			*temperature_up_d = cali_info->delta_swing_table_idx_2g_cck_d_p;
			*temperature_down_d = cali_info->delta_swing_table_idx_2g_cck_d_n;
		} else {
			*temperature_up_c = cali_info->delta_swing_table_idx_2gc_p;
			*temperature_down_c = cali_info->delta_swing_table_idx_2gc_n;
			*temperature_up_d = cali_info->delta_swing_table_idx_2gd_p;
			*temperature_down_d = cali_info->delta_swing_table_idx_2gd_n;
		}
	}

	if (channel >= 36 && channel <= 64) {
		*temperature_up_c = cali_info->delta_swing_table_idx_5gc_p[0];
		*temperature_down_c = cali_info->delta_swing_table_idx_5gc_n[0];
		*temperature_up_d = cali_info->delta_swing_table_idx_5gd_p[0];
		*temperature_down_d = cali_info->delta_swing_table_idx_5gd_n[0];
	} else if (channel >= 100 && channel <= 144) {
		*temperature_up_c = cali_info->delta_swing_table_idx_5gc_p[1];
		*temperature_down_c = cali_info->delta_swing_table_idx_5gc_n[1];
		*temperature_up_d = cali_info->delta_swing_table_idx_5gd_p[1];
		*temperature_down_d = cali_info->delta_swing_table_idx_5gd_n[1];
	} else if (channel >= 149 && channel <= 177) {
		*temperature_up_c = cali_info->delta_swing_table_idx_5gc_p[2];
		*temperature_down_c = cali_info->delta_swing_table_idx_5gc_n[2];
		*temperature_up_d = cali_info->delta_swing_table_idx_5gd_p[2];
		*temperature_down_d = cali_info->delta_swing_table_idx_5gd_n[2];
	}
}


void halrf_dack_setbb_8814b(struct dm_struct *dm)
{
	/*BB setting*/
	odm_set_bb_reg(dm, 0x1d58, 0xff8, 0x1ff);
	odm_set_bb_reg(dm, 0x1a00, 0x3, 0x2);
	odm_set_bb_reg(dm, 0x1a14, 0x300, 0x3);
	odm_write_4byte(dm, 0x1d70, 0x7e7e7e7e);
	odm_set_bb_reg(dm, 0x180c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x410c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x520c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x530c, 0x3, 0x0);
	odm_write_4byte(dm, 0x1b00, 0x00000008);
	odm_write_1byte(dm, 0x1bcc, 0x3f);
	odm_write_4byte(dm, 0x1b00, 0x0000000a);
	odm_write_1byte(dm, 0x1bcc, 0x3f);
	odm_write_4byte(dm, 0x1b00, 0x0000000c);
	odm_write_1byte(dm, 0x1bcc, 0x3f);
	odm_write_4byte(dm, 0x1b00, 0x0000000e);
	odm_write_1byte(dm, 0x1bcc, 0x3f);
	odm_set_bb_reg(dm, 0x1e24, BIT(31), 0x0);
	odm_set_bb_reg(dm, 0x1e28, 0xf, 0x3);
	odm_set_rf_reg(dm, RF_PATH_A, 0x0, RFREG_MASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_B, 0x0, RFREG_MASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_C, 0x0, RFREG_MASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_D, 0x0, RFREG_MASK, 0x10000);
}

#define REGA 0x1800
#define REGB 0x4100
#define REGC 0x5200
#define REGD 0x5300

u32 halrf_pathsel1_8814b(struct dm_struct *dm, u8 path)
{
	switch (path) {
	case 0:
		return 0x1800;
		break;
	case 1:
		return 0x4100;
		break;
	case 2:
		return 0x5200;
		break;
	case 3:
		return 0x5300;
		break;
	default:
		return 0x1800;
		break;

	}
}


u32 halrf_pathsel2_8814b(struct dm_struct *dm, u8 path)
{
	switch (path) {
	case 0:
		return 0x2800;
		break;
	case 1:
		return 0x4500;
		break;
	case 2:
		return 0x5600;
		break;
	case 3:
		return 0x5700;
		break;
	default:
		return 0x2800;
		break;

	}
}


void halrf_dack1_8814b(struct dm_struct *dm, u8 path, u32 *iadc, u32 *qadc,
	              u32 *v1, u32 *v2)
{
	u8 i;
	u32 p, idc, qdc, ic, qc, abs_idc, abs_qdc, temp, adc_temp;

	p = halrf_pathsel1_8814b(dm, path);
	RF_DBG(dm, DBG_RF_DACK, "[DACK]S%d DACK1!!!!!!!!!!!!!!!!!!!!!!", path);
	
	odm_set_bb_reg(dm, p + 0x30, BIT(30), 0x0);
//	odm_write_4byte(dm, p + 0x30, 0x300f0000);
	odm_write_4byte(dm, p + 0x60, 0xf0040ff0);
	odm_write_4byte(dm, 0x9b4, 0xdb66db00);
	odm_write_4byte(dm, p + 0x10, 0x000dc304);
	odm_write_4byte(dm, p + 0x0c, 0x10000260);
	i = 0;
	while (i < 10) {
		ic = qc = 0;
		i++;
		RF_DBG(dm, DBG_RF_DACK, "[DACK]DACK1 times=%d", i);
		odm_write_4byte(dm, 0x1c3c, 0x00088003 | path << 17);
		odm_write_4byte(dm, 0x1c24, 0x00010002);
		halrf_mode(dm, &idc, &qdc);
		RF_DBG(dm, DBG_RF_DACK, "[DACK]before ADCK i=0x%x qc=0x%x",
		       idc, qdc);
		/*compensation value*/
		if (idc != 0x0)
			ic = 0x400 - idc;
		if (qdc != 0x0)
			qc = 0x400 - qdc;
		*v1 = (ic & 0x3ff) | ((qc & 0x3ff) << 10);
		odm_write_4byte(dm, p + 0x68, *v1);
		RF_DBG(dm, DBG_RF_DACK, "[DACK]ADCK 0xXX68_1 =0x%x", *v1);
#if 1
		/*check ADC DC offset*/
		odm_write_4byte(dm, 0x1c3c, 0x00088103 | path << 17);
		halrf_mode(dm, &idc, &qdc);
		iadc[path] = idc;
		qadc[path] = qdc;
		RF_DBG(dm, DBG_RF_DACK, "[DACK]after ADCK i=0x%x q=0x%x",
		       idc, qdc);
#endif
		if (idc >= 0x200)
			abs_idc = 0x400 - idc;
		else
			abs_idc = idc;
		if (qdc >= 0x200)
			abs_qdc = 0x400 - qdc;
		else
			abs_qdc = qdc;
		if (abs_idc < 5 &&  abs_qdc < 5)
			break;
	}

	if (ic < 0x300) {
		ic = ic + 0x80;
	} else {
		ic = 0x80 - (0x400 - ic);
	}
	if (qc < 0x300) {
		qc = qc + 0x80;
	} else {
		qc = 0x80 - (0x400 - qc);
	}
	*v2 = (ic & 0x3ff) | ((qc & 0x3ff) << 10);
}

void halrf_dack2_8814b(struct dm_struct *dm, u8 path, u32 *idac, u32 *qdac,
		       u32 v1, u32 v2)
{
	u8 i, c;
	u32 p, pr, idc, qdc;
	
	RF_DBG(dm, DBG_RF_DACK, "[DACK]S%d DACK2!!!!!!!!!!!!!!!!!!!!!!", path);
	p = halrf_pathsel1_8814b(dm, path);
	pr = halrf_pathsel2_8814b(dm, path);
	i = 0;
	while (i < 10) {
		i++;
		RF_DBG(dm, DBG_RF_DACK, "[DACK]DACK2 times=%d", i);
		odm_write_4byte(dm, p + 0x68, v1);
		RF_DBG(dm, DBG_RF_DACK, "[DACK]ADCK 0xXX68_2=0x%x\n", v1);
		odm_write_4byte(dm, p + 0x10, 0x0005C304);
		odm_write_4byte(dm, p + 0x0c, 0x50000260);
		/*3.release pull low switch on IQ path*/
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8f, BIT(13), 0x1);
		odm_write_4byte(dm, p + 0x10, 0x0005c305);
		odm_write_4byte(dm, p + 0xbc, 0x0003ff81);
		odm_write_4byte(dm, p + 0xb0, 0x0a187ff8);
		odm_write_4byte(dm, p + 0xb4, 0x00000000);
		odm_write_4byte(dm, p + 0xb8, 0x00000000);
		odm_write_4byte(dm, p + 0xbc, 0x2403ff81);
		odm_write_4byte(dm, p + 0xc0, 0x80005308);
		odm_write_4byte(dm, p + 0xc4, 0x01000000);
		odm_write_4byte(dm, p + 0xc8, 0x001dffe0);
		odm_write_4byte(dm, p + 0xcc, 0x0a187fe8);
		odm_write_4byte(dm, p + 0xd0, 0x00000000);
		odm_write_4byte(dm, p + 0xd4, 0x00000000);
		odm_write_4byte(dm, p + 0xd8, 0x2403ff81);
		odm_write_4byte(dm, p + 0xdc, 0x80005308);
		odm_write_4byte(dm, p + 0xe0, 0x01000000);
		odm_write_4byte(dm, p + 0xe4, 0x001dffe0);
		odm_write_4byte(dm, p + 0xb0, 0x0a187fe9);
		odm_write_4byte(dm, p + 0xcc, 0x0a187fe9);
		odm_write_4byte(dm, p + 0xbc, 0x2503ff81);
		odm_write_4byte(dm, p + 0xd8, 0x2503ff81);
		//DAC MSB K
		odm_write_4byte(dm, p + 0xb8, 0x60000000);
		odm_write_4byte(dm, p + 0xd4, 0x60000000);
		ODM_delay_ms(1);
		odm_write_4byte(dm, p + 0xb8, 0x62000000);
		odm_write_4byte(dm, p + 0xd4, 0x62000000);
		ODM_delay_ms(10);
		c = 0;
		while (c < 30) {
			if (odm_get_bb_reg(dm, pr + 0x08, 0x7fff80) == 0xffff &&
			    odm_get_bb_reg(dm, pr + 0x34, 0x7fff80) == 0xffff &&
			    odm_get_bb_reg(dm, pr + 0x10, 0x2) == 0x1 &&
			    odm_get_bb_reg(dm, pr + 0x3c, 0x2) == 0x1)			    
				break;
			else
				c++;
			ODM_delay_ms(1);

			if (c == 30)
				RF_DBG(dm, DBG_RF_DACK, "[DACK]timeout!!!");
		}
		odm_write_4byte(dm, p + 0xb8, 0x02000000);
		odm_write_4byte(dm, p + 0xd4, 0x02000000);
		//DAC dcoffset K
		odm_write_4byte(dm, p + 0xc8, 0x000dffe0);
		odm_write_4byte(dm, p + 0xe4, 0x000dffe0);
		odm_write_4byte(dm, p + 0xbc, 0x2d03ff81);
		ODM_delay_ms(1);
		c = 0;
		while (c < 30) {
			if (odm_get_bb_reg(dm, pr + 0x2c, 0xff000) == 0xff)			    
				break;
			else
				c++;
			ODM_delay_ms(1);

			if (c == 30)
				RF_DBG(dm, DBG_RF_DACK, "[DACK]timeout!!!");
		}
		odm_write_4byte(dm, p + 0xd8, 0x2d03ff81);
		ODM_delay_ms(1);
		c = 0;
		while (c < 30) {
			if (odm_get_bb_reg(dm, pr + 0x58, 0xff000) == 0xff)			    
				break;
			else
				c++;
			ODM_delay_ms(1);

			if (c == 30)
				RF_DBG(dm, DBG_RF_DACK, "[DACK]timeout!!!");
		}
		odm_write_4byte(dm, p + 0xc8, 0x001dffe0);
		odm_write_4byte(dm, p + 0xe4, 0x001dffe0);
		odm_write_4byte(dm, p + 0x68, v2);
		RF_DBG(dm, DBG_RF_DACK, "[DACK]ADCK 0xXX68_3 =0x%x", v2);
		odm_write_4byte(dm, 0x9b4, 0xdb6db600);
		/*check DAC DC offset*/
		odm_write_4byte(dm, 0x1c3c, 0x00088103 | path << 17);
		odm_write_4byte(dm, p + 0x10, 0x0005c305);
		odm_write_4byte(dm, p + 0xbc, 0x2d03ff81);
//		odm_write_4byte(dm, p + 0x30, 0x300f1000);
		odm_write_4byte(dm, p + 0x60, 0xf0040ff0);
		halrf_mode(dm, &idc, &qdc);
		idac[path] = idc;
		qdac[path] = qdc;
		RF_DBG(dm, DBG_RF_DACK, "[DACK]after DACK i=0x%x q=0x%x",
		       idc, qdc);
		if (idc >= 0x200)
			idc = 0x400 - idc;
		if (qdc >= 0x200)
			qdc = 0x400 - qdc;
		if (idc < 5 && qdc < 5)
			break;
	}
}

void halrf_dack_reload_8814b(struct dm_struct *dm)
{
	u8 i;
	u32 p;
	
	for (i = 0; i < 4; i++) {
		p = halrf_pathsel1_8814b(dm, i);
//		odm_write_4byte(dm, p + 0x10, 0x0005c304);
//		odm_write_4byte(dm, p + 0xbc, 0x2d03ff80);
		odm_set_bb_reg(dm, p + 0x30, BIT(30), 0x1);
//		odm_write_4byte(dm, p + 0x30, 0x700f1000);
//		odm_write_4byte(dm, p + 0x60, 0xf0041ff0);
		odm_write_4byte(dm, 0x1b00, 0x00000008 | i << 1);
		odm_write_1byte(dm, 0x1bcc, 0x00);
	}
}

void halrf_do_rxbb_dck_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 i = 0, path = 0x0;

	RF_DBG(dm, DBG_RF_IQK, "[DACK]RXBB DCK start!!!!!!!\n");
	for (path = 0; i < 4; i++) {		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8f, BIT(12), 0x1);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x69, 0x3f, 0x3f);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x67, BIT(0), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x67, BIT(0), 0x1);
		for ( i = 0; i < 10; i++)
			ODM_delay_us(40);

		odm_set_rf_reg(dm, (enum rf_path)path, 0x67, BIT(0), 0x0);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0xdf, BIT(13), 0x1);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x82, 0x70, 0x6);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x82, 0x0e, 0x2);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x68, BIT(4), 0x1);
		for ( i = 0; i < 10; i++)
			ODM_delay_us(10);
		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x68, BIT(4), 0x0);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x82, 0x7, 0x5);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x82, 0x0e, 0x2);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x68, BIT(4), 0x1);
		for ( i = 0; i < 10; i++)
			ODM_delay_us(10);
		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x68, BIT(4), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, 0xdf, BIT(13), 0x0);
	}
	
	RF_DBG(dm, DBG_RF_IQK, "[DACK]RXBB DCK end!!!!!!!\n");
}

void halrf_dac_cal_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	static u32 count = 0;

	u8 i;
	u32 temp = 0, v1, v2;
	u32 iadc[4], qadc[4], idac[4], qdac[4];
	u32 bp[DACK_REG_8814B];
	u32 bp_reg[DACK_REG_8814B] = {0x180c, 0x410c, 0x520c, 0x530c, 0x1c3c,
				      0x1c24, 0x1d70, 0x9b4, 0x1a00, 0x1a14,
				      0x1d58, 0x1c38, 0x1e24, 0x1e28, 0x1860, 
				      0x4160, 0x5260, 0x5360, 0x1810, 0x4110,
				      0x5210, 0x5310, 0x18bc, 0x41bc, 0x52bc,
				      0x53bc};
	u32 bp_rf[DACK_RF_8814B][4];
	u32 bp_rfreg[DACK_RF_8814B] = {0x8f};

	count++;
	RF_DBG(dm, DBG_RF_DACK, "[DACK]count = %d", count);
	RF_DBG(dm, DBG_RF_DACK, "[DACK]DACK start!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	halrf_bp(dm, bp_reg, bp, DACK_REG_8814B);
	halrf_bprf(dm, bp_rfreg, bp_rf,DACK_RF_8814B, 4);
	halrf_dack_setbb_8814b(dm);
	for (i = 0; i < 4; i++) {
		halrf_dack1_8814b(dm, i, iadc, qadc, &v1, &v2);
		halrf_dack2_8814b(dm, i, idac, qdac, v2, v1);
	}
	halrf_dack_reload_8814b(dm);
	halrf_reload_bp(dm, bp_reg, bp, DACK_REG_8814B);
	halrf_reload_bprf(dm,bp_rfreg, bp_rf, DACK_RF_8814B, 4);
	for (i = 0; i < 4; i++)
		RF_DBG(dm, DBG_RF_DACK, "[DACK]ADCK S%d:i= 0x%3x q= 0x%3x", i,
		       iadc[i], qadc[i]);
	for (i = 0; i < 4; i++)
		RF_DBG(dm, DBG_RF_DACK, "[DACK]DACK S%d:i= 0x%3x q= 0x%3x", i,
		       idac[i], qdac[i]);
	RF_DBG(dm, DBG_RF_DACK, "[DACK]DACK end!!!!!!!\n");
}


void _phy_lc_calibrate_8814b(struct dm_struct *dm)
{
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
	for (cnt = 0; cnt < 5; cnt++) {
		if (odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, 0x8000) != 0x1)
			break;
		ODM_delay_ms(10);
	}
	if (cnt == 5)
		RF_DBG(dm, DBG_RF_LCK, "LCK time out\n");
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
}

void _phy_rtc_8814b(struct dm_struct *dm)
{
	u32  tmp0xc, cv_offset;

	RF_DBG(dm, DBG_RF_LCK, "[LCK]RTC start!!!!!!!\n");
	tmp0xc  =  config_phydm_read_syn_reg_8814b(dm, RF_SYN0, 0xc, RFREG_MASK);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, 0xc, RFREG_MASK, tmp0xc & ~BIT(2));
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, 0xc, RFREG_MASK, tmp0xc | BIT(2));
	tmp0xc  =  config_phydm_read_syn_reg_8814b(dm, RF_SYN1, 0xc, RFREG_MASK);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, 0xc, RFREG_MASK, tmp0xc & ~BIT(2));
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, 0xc, RFREG_MASK, tmp0xc | BIT(2));
#if 0
	cv_offset = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, 0xd, 0xf0000);
	RF_DBG(dm, DBG_RF_LCK, "[LCK]SYN0 CV_offset = %x\n", cv_offset);
	cv_offset = config_phydm_read_syn_reg_8814b(dm, RF_SYN1, 0xd, 0xf0000);
	RF_DBG(dm, DBG_RF_LCK, "[LCK]SYN1 CV_offset = %x\n", cv_offset);
#endif
	RF_DBG(dm, DBG_RF_LCK, "[LCK]RTC end!!!!!!!\n");
}




/*LCK VERSION:0x1*/
void phy_lc_calibrate_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	_phy_rtc_8814b(dm);
}

void configure_txpower_track_8814b(struct txpwrtrack_cfg *config)
{
	config->swing_table_size_cck = TXSCALE_TABLE_SIZE;
	config->swing_table_size_ofdm = TXSCALE_TABLE_SIZE;
	config->threshold_iqk = IQK_THRESHOLD;
	config->threshold_dpk = DPK_THRESHOLD;
	config->average_thermal_num = AVG_THERMAL_NUM_8814B;
	config->rf_path_count = MAX_PATH_NUM_8814B;
	config->thermal_reg_addr = RF_T_METER_8814B;

	config->odm_tx_pwr_track_set_pwr = odm_tx_pwr_track_set_pwr8814b;
	config->do_iqk = do_iqk_8814b;
	config->phy_lc_calibrate = halrf_lck_trigger;
	config->do_tssi_dck = halrf_tssi_dck;
	config->get_delta_swing_table = get_delta_swing_table_8814b;
	config->get_delta_swing_table8814only = get_delta_swing_table_8814b_path_cd;
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
void phy_set_rf_path_switch_8814b(struct dm_struct *dm, boolean is_main)
#else
void phy_set_rf_path_switch_8814b(void *adapter, boolean is_main)
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

#if 0
	/*odm_set_bb_reg(dm, R_0x1991, 0x3, 0x0);*/
#endif
	odm_set_bb_reg(dm, R_0x1990, (BIT(9) | BIT(8)), 0x0);

#if 0
	/*odm_set_bb_reg(dm, R_0xcbe, 0x8, 0x0);*/
#endif
	odm_set_bb_reg(dm, R_0xcbc, BIT(19), 0x0);

	odm_set_bb_reg(dm, R_0xcb4, 0xff, 0x77);

	odm_set_bb_reg(dm, R_0x70, MASKBYTE3, 0x0e);
	odm_set_bb_reg(dm, R_0x1704, MASKDWORD, 0x0000ff00);
	odm_set_bb_reg(dm, R_0x1700, MASKDWORD, 0xc00f0038);

	if (is_main) {
#if 0
		/*odm_set_bb_reg(dm, R_0xcbd, 0x3, 0x2); WiFi*/
#endif
		odm_set_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8)), 0x2); /*WiFi*/
	} else {
#if 0
		/*odm_set_bb_reg(dm, R_0xcbd, 0x3, 0x1); BT*/
#endif
		odm_set_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8)), 0x1); /*BT*/
	}
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
boolean _phy_query_rf_path_switch_8814b(struct dm_struct *dm)
#else
boolean _phy_query_rf_path_switch_8814b(void *adapter)
#endif
{
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
	HAL_DATA_TYPE *hal_data = GET_HAL_DATA(((PADAPTER)adapter));
	struct dm_struct *dm = &hal_data->DM_OutSrc;
#endif
#endif
	if (odm_get_bb_reg(dm, R_0xcbc, (BIT(9) | BIT(8))) == 0x2) /*WiFi*/
		return true;
	else
		return false;
}

#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
boolean phy_query_rf_path_switch_8814b(struct dm_struct *dm)
#else
boolean phy_query_rf_path_switch_8814b(void *adapter)
#endif
{
#if DISABLE_BB_RF
	return true;
#endif
#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
	return _phy_query_rf_path_switch_8814b(dm);
#else
	return _phy_query_rf_path_switch_8814b(adapter);
#endif
}

#endif /*(RTL8814B_SUPPORT == 0)*/
