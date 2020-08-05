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

#ifndef __HALRF_IQK_8197G_H__
#define __HALRF_IQK_8197G_H__

#if (RTL8197G_SUPPORT == 1)
/*--------------------------Define Parameters-------------------------------*/
#define MAC_REG_NUM_8197G 1
#define BB_REG_NUM_8197G 8
#define RF_REG_NUM_8197G 2
#define IQK_DELAY_8197G 1
#define IQK_STEP_8197G 7
#define RXK_STEP_8197G 6
#define IQK_CMD_8197G 0x8

#define TXIQK 0
#define RXIQK 1
#define SS_8197G 2
/*---------------------------End Define Parameters-------------------------------*/
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void do_iqk_8197g(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold);
#else
void do_iqk_8197g(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold);
#endif

void phy_iq_calibrate_8197g(
	void *dm_void,
	boolean clear,
	boolean segment_iqk);

void do_imr_test_8197g(
	void *dm_void);

void do_lok_8197g(
	void *dm_void);

#else /* (RTL8197G_SUPPORT == 0)*/

#define phy_iq_calibrate_8197g(_pdm_void, clear, segment_iqk)

#endif /* RTL8197G_SUPPORT */

#endif /*__HALRF_IQK_8197G_H__*/
