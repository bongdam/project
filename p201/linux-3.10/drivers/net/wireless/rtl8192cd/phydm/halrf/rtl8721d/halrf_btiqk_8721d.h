/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018  Realtek Corporation.
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

#ifndef __HALRF_8721D_H__
#define __HALRF_8721D_H__

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
#define BTIQK_DELAY_TIME_8721D 15 /* ms */
#else
#define BTIQK_DELAY_TIME_8721D 10
#endif
#define MAX_TOLERANCE 5

#define BTIQK_BB_REG_NUM_8721D 9
#define BTIQK_RF_REG_NUM_8721D 6
#define BTIQK_MAC_REG_NUM_8721D 2

#if 1
void
phy_bt_adda_dck_8721d(void *dm_void);
#else
void phy_bt_adc_dck_8721d(void *dm_void);
void phy_bt_dac_dck_8721d(void *dm_void);
#endif

void
phy_bt_lok_write_8721d(struct dm_struct *dm,
		       u32 lok_xx,
		       u32 lok_yy);

void phy_bt_dck_write_8721d(struct dm_struct *dm,
			    u8 q_dck,
			    u8 i_dck);

u32
phy_btiq_calibrate_8721d(struct dm_struct *dm);

#endif /*__HALRF_8721D_H__*/
