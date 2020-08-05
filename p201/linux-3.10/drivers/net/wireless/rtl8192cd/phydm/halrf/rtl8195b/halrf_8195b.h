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

#ifndef __HALRF_8195B_H__
#define __HALRF_8195B_H__

#define AVG_THERMAL_NUM_8195B 4
#define RF_T_METER_8195B 0x42

void configure_txpower_track_8195b(
	struct txpwrtrack_cfg *p_config);

void odm_tx_pwr_track_set_pwr8195b(
	void *p_dm_void,
	enum pwrtrack_method method,
	u8 rf_path,
	u8 channel_mapped_index);

void get_delta_swing_table_8195b(
	void *dm_void,
	u8 **temperature_up_a,
	u8 **temperature_down_a,
	u8 **temperature_up_b,
	u8 **temperature_down_b);

void odm_txxtaltrack_set_xtal_8195b(
	void *dm_void);

void phy_lc_calibrate_8195b(
	void *p_dm_void);

void halrf_rf_lna_setting_8195b(
	struct dm_struct *p_dm_void,
	enum halrf_lna_set type);
void phy_set_rf_path_switch_8195b(
	struct dm_struct *dm,
	boolean is_main);

boolean phy_query_rf_path_switch_8195b(
	struct dm_struct *dm);

#endif /* #ifndef __HALRF_8195B_H__ */
