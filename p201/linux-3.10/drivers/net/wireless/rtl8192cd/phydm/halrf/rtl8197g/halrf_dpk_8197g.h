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

#ifndef __HALRF_DPK_8197G_H__
#define __HALRF_DPK_8197G_H__

#if (RTL8197G_SUPPORT == 1)
/*--------------------------Define Parameters-------------------------------*/
#define DPK_RF_PATH_NUM_8197G 2
#define DPK_GROUP_NUM_8197G 1
#define DPK_MAC_REG_NUM_8197G 2
#define DPK_BB_REG_NUM_8197G 13
#define DPK_RF_REG_NUM_8197G 2
#define DPK_PAS_DBG_8197G 0
#define DPK_SRAM_IQ_DBG_8197G 0
#define DPK_SRAM_read_DBG_8197G 0
#define DPK_SRAM_write_DBG_8197G 0
#define DPK_DO_PATH_A 1
#define DPK_DO_PATH_B 1
#define DPK_THRESHOLD_8197G 6
/*---------------------------End Define Parameters----------------------------*/

u8 dpk_channel_transfer_8197g(
	void *dm_void);

void dpk_sram_read_8197g(
	void *dm_void);

void dpk_enable_disable_8197g(
	void *dm_void);

void dpk_reload_8197g(
	void *dm_void);

void do_dpk_8197g(
	void *dm_void);

void dpk_track_8197g(
	void *dm_void);

void dpk_info_by_8197g(
	void *dm_void,
	u32 *_used,
	char *output,
	u32 *_out_len);

#endif /* RTL8197G_SUPPORT */

#endif /*#ifndef __HALRF_DPK_8197G_H__*/
