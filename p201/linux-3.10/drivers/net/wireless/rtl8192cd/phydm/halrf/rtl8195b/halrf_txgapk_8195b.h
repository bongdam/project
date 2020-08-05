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

#ifndef __HALRF_TXGAPK_8195B_H__
#define __HALRF_TXGAPK_8195B_H__

#if (RTL8195B_SUPPORT == 1)
/*============================================================*/
/*Definition */
/*============================================================*/

/*--------------------------Define Parameters-------------------------------*/
#define GAPK_MAC_REG_NUM_8195B 3
#define GAPK_BB_REG_NUM_8195B 13
#define GAPK_RF_REG_NUM_8195B 5
#define GAPK_SS_8195B 1
#define GAPK_VERSION_8195B 2

/*---------------------------End Define Parameters-------------------------------*/

void do_txgapk_8195b(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold);

void phy_txgap_calibrate_8195b(
	void *dm_void,
	boolean clear

	);

#else /* (RTL8195B_SUPPORT == 0)*/

//#define phy_txgap_calibrate_8195b(_pDM_VOID, clear)
#define do_txgapk_8195b(_pDM_VOID, clear)

#endif /* RTL8195B_SUPPORT */

#endif /*#ifndef __HALRF_IQK_8195B_H__*/
