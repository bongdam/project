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

#ifndef __HALRF_8814B_H__
#define __HALRF_8814B_H__

#define AVG_THERMAL_NUM_8814B 4
#define RF_T_METER_8814B 0x42
#define DACK_REG_8814B 26
#define DACK_RF_8814B 1

u8 halrf_do_tssi_8814b(void *dm_void, u8 rf_path);

void halrf_trigger_tssi_8814b(	void *dm_void, u8 rf_path);

u8 halrf_get_tssi_result_8814b(void *dm_void, u8 rf_path);

void halrf_calculate_tssi_codeword_8814b(void *dm_void, u8 rf_path);

void halrf_set_tssi_codeword_8814b(void *dm_void, u16 *tssi_value);

u8 halrf_get_tssi_codeword_8814b(void *dm_void);

u32 halrf_query_tssi_value_8814b(void *dm_void);

u32 halrf_set_tssi_value_8814b(void *dm_void, u32 tssi_codeowrd);

void halrf_tssi_get_efuse_8814b(void *dm_void);

void halrf_get_efuse_thermal_pwrtype_8814b(void *dm_void);

void halrf_tssi_set_de_8814b(void *dm_void);

void halrf_tssi_set_de_for_tx_verify_8814b(
	void *dm_void, u32 tssi_de, u8 path);

void halrf_tssi_clean_de_8814b(void *dm_void);

u32 halrf_tssi_trigger_de_8814b(void *dm_void, u8 path);

u32 halrf_tssi_get_de_8814b(void *dm_void, u8 path);

void halrf_tssi_dck_8814b(void *dm_void, u8 direct_do);

void configure_txpower_track_8814b(struct txpwrtrack_cfg *config);

void odm_tx_pwr_track_set_pwr8814b(void *dm_void, enum pwrtrack_method method,
				   u8 rf_path, u8 channel_mapped_index);

void get_delta_swing_table_8814b(void *dm_void,
				 u8 **temperature_up_a,
				 u8 **temperature_down_a,
				 u8 **temperature_up_b,
				 u8 **temperature_down_b);

void halrf_dac_cal_8814b(void *dm_void);

void phy_lc_calibrate_8814b(void *dm_void);

void halrf_rf_lna_setting_8814b(struct dm_struct *dm, enum halrf_lna_set type);

void halrf_do_rxbb_dck_8814b(void *dm_void);


#if ((DM_ODM_SUPPORT_TYPE & ODM_AP) || (DM_ODM_SUPPORT_TYPE == ODM_CE))
void phy_set_rf_path_switch_8814b(struct dm_struct *dm,
#else
void phy_set_rf_path_switch_8814b(void *adapter,
#endif
				  boolean is_main);

#endif /*__HALRF_8814B_H__*/
