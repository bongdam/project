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

#ifndef __HALRF_8710C_H__
#define __HALRF_8710C_H__

#if (DM_ODM_SUPPORT_TYPE & (ODM_WIN))
#if RT_PLATFORM == PLATFORM_MACOSX
#include "halphyrf_win.h"
#else
#include "../halrf/halphyrf_win.h"
#endif
#elif (DM_ODM_SUPPORT_TYPE & (ODM_CE))
#include "../halphyrf_ce.h"
#elif (DM_ODM_SUPPORT_TYPE & (ODM_AP))
#include "../halphyrf_ap.h"
#endif

/*--------------------------Define Parameters-------------------------------*/

#if (DM_ODM_SUPPORT_TYPE & ODM_CE)
#define IQK_DELAY_TIME_8710C 15 /* ms */
#else
#define IQK_DELAY_TIME_8710C 10
#endif

#define index_mapping_NUM_8710C 15

#define AVG_THERMAL_NUM_8710C 4
#define RF_T_METER_8710C 0x42

void
configure_txpower_track_8710c(struct txpwrtrack_cfg *p_config);

void
odm_tx_pwr_track_set_pwr_8710c(void *dm_void,
			       enum pwrtrack_method method,
			       u8 rf_path,
			       u8 channel_mapped_index);

void
get_delta_swing_table_8710c(void *dm_void,
			    u8 **temperature_up_a,
			    u8 **temperature_down_a,
			    u8 **temperature_up_cck_a,
			    u8 **temperature_down_cck_a);

void
get_delta_swing_xtal_table_8710c(void *dm_void,
				 s8 **temperature_up_xtal,
				 s8 **temperature_down_xtal);

void
odm_txxtaltrack_set_xtal_8710c(void *dm_void);

void
phy_lc_calibrate_8710c(void *dm_void);

void
phy_set_rf_path_switch_8710c(
	struct dm_struct *dm,
	boolean is_main);

void 
phy_poll_lck_8710c(struct dm_struct *dm);
#endif /*__HALRF_8192F_H__*/
