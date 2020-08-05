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

#ifndef __HALRF_TSSI_8197G_H__
#define __HALRF_TSSI_8197G_H__

#if (RTL8197G_SUPPORT == 1)

/*--------------------------Define Parameters-------------------------------*/

/*---------------------------End Define Parameters----------------------------*/

void halrf_tssi_dck_8197g(
	void *dm_void);

void halrf_tssi_clean_de_8197g(
	void *dm_void);

u32 halrf_tssi_trigger_de_8197g(
	void *dm_void, u8 path);

u32 halrf_tssi_get_de_8197g(
	void *dm_void, u8 path);

u8 halrf_get_tssi_codeword_8197g(
	void *dm_void);

void halrf_tssi_get_efuse_8197g(
	void *dm_void);

void halrf_tssi_get_kfree_efuse_8197g(
	void *dm_void);

void halrf_enable_tssi_8197g(
	void *dm_void);

void halrf_disable_tssi_8197g(
	void *dm_void);

void halrf_do_tssi_8197g(
	void *dm_void);

void halrf_do_thermal_8197g(
	void *dm_void);

u32 halrf_set_tssi_value_8197g(
	void *dm_void,
	u32 tssi_value);

void halrf_set_tssi_poewr_8197g(
	void *dm_void,
	s8 power);

u32 halrf_query_tssi_value_8197g(
	void *dm_void);

void halrf_tssi_cck_8197g(
	void *dm_void);

void halrf_thermal_cck_8197g(
	void *dm_void);

#endif /* RTL8197G_SUPPORT */
#endif /*#ifndef __HALRF_TSSI_8197G_H__*/
