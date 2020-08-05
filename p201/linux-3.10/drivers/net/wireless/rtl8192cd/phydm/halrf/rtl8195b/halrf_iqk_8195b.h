/******************************************************************************
 *
 * Copyright(c) 2016 - 2017 Realtek Corporation.
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

#ifndef __HALRF_IQK_8195B_H__
#define __HALRF_IQK_8195B_H__

#if (RTL8195B_SUPPORT == 1)
/*============================================================*/
/*Definition */
/*============================================================*/

/*--------------------------Define Parameters-------------------------------*/

#define IQK_MAC_REG_NUM_8195B 3
#define IQK_BB_REG_NUM_8195B 11
#define IQK_RF_REG_NUM_8195B 6

#define LOK_delay_8195B 2
#define GS_delay_8195B 2
#define WBIQK_delay_8195B 2

#define TXIQK 0
#define RXIQK 1
#define SS_8195B 1

/*---------------------------End Define Parameters-------------------------------*/

#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void do_iqk_8195b(
	void *p_dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold);
#else
void do_iqk_8195b(
	void *p_dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold);
#endif

void do_imr_test_8195b(
	void *p_dm_void);

void phy_iq_calibrate_8195b(
	void *dm_void,
	boolean clear,
	boolean segment_iqk);

#else /* (RTL8195B_SUPPORT == 0)*/

#define phy_iq_calibrate_8195b(_pdm_void, clear, segment_iqk)

#endif /* RTL8195B_SUPPORT */

#endif /*#ifndef __HALRF_IQK_8195B_H__*/
