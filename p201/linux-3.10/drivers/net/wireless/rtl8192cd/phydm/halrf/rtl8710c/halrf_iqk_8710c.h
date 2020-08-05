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

#ifndef __HALRF_IQK_8710C_H__
#define __HALRF_IQK_8710C_H__

#if (RTL8710C_SUPPORT == 1)
/*@--------------------------Define Parameters-------------------------------*/
#define MAC_NUM_8710C 1
#define BB_NUM_8710C 5
#define RF_NUM_8710C 2

#define IQK_DELAY_8710C 1
#define IQK_STEP_8710C 5
#define RXK_STEP_8710C 4

#define TXIQK 0
#define RXIQK 1
#define SS_8710C 1
/*@-------------------------End Define Parameters-------------------------*/
void do_iqk_8710c(void *dm_void, u8 delta_thermal_index, u8 thermal_value,
		  u8 threshold);

void phy_iq_calibrate_8710c(void *dm_void, boolean clear, boolean segment_iqk);

#else /* (RTL8710C_SUPPORT == 0)*/

#define phy_iq_calibrate_8710c(_pdm_void, clear, segment_iqk)

#endif /* RTL8710C_SUPPORT */

#endif /*__HALRF_IQK_8710C_H__*/
