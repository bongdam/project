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

#ifndef __HALRF_DPK_8195B_H__
#define __HALRF_DPK_8195B_H__

#if (RTL8195B_SUPPORT == 1)
/*--------------------------Define Parameters-------------------------------*/
#define DPK_VERSION_8195B 6
#define DPK_RF_PATH_NUM_8195B 1
#define DPK_GROUP_NUM_8195B 16
#define G_2G_N 3
#define G_5G_N 13
#define DPK_MAC_REG_NUM_8195B 3
#define DPK_BB_REG_NUM_8195B 29
#define DPK_RF_REG_NUM_8195B 8
#define DPK_PAS_DBG_8195B 0
#define DPK_SRAM_IQ_DBG_8195B 0
#define DPK_SRAM_read_DBG_8195B 1
#define DPK_SRAM_write_DBG_8195B 1
#define DPK_DO_PATH_A 1
#define DPK_DO_PATH_B 0
#define DPK_DO_PATH_C 0
#define DPK_DO_PATH_D 0
#define DPK_THRESHOLD_8195B 5
#define GSK1 0x1
#define GSK2 0x2
#define GSK3 0x3

/*---------------------------End Define Parameters----------------------------*/

u8 dpk_channel_transfer_8195b(void *dm_void);

void dpk_sram_read_8195b(void *dm_void);

void dpk_enable_disable_8195b(void *dm_void);

void dpk_reload_8195b(void *dm_void);

void do_dpk_8195b(void *dm_void);

void dpk_track_8195b(void *dm_void);

void dpk_result_summary_8195b(void *dm_void);

void dpk_by_group_8195b(void *dm_void);

void dpk_set_dpkbychannel_8195b(void *dm_void, boolean dpk_by_ch);

boolean dpk_get_dpkbychannel_8195b(void *dm_void);

void dpk_set_is_dpk_enable_8195b(void *dm_void, boolean is_dpk_enable);

boolean dpk_get_is_dpk_enable_8195b(void *dm_void);


#endif /* RTL8195B_SUPPORT */

#endif /*#ifndef __HALRF_DPK_8195B_H__*/
