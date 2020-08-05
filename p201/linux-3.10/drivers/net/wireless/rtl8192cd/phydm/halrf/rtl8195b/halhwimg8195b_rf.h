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

/*Image2HeaderVersion: R3 1.5.5*/
#if (RTL8195B_SUPPORT == 1)
#ifndef __INC_MP_RF_HW_IMG_8195B_H
#define __INC_MP_RF_HW_IMG_8195B_H

/* Please add following compiler flags definition (#define CONFIG_XXX_DRV_DIS)
 * into driver source code to reduce code size if necessary.
 * #define CONFIG_8195B_DRV_DIS
 * #define CONFIG_8195B_PKG1_DRV_DIS
 */

#define CONFIG_8195B
#ifdef CONFIG_8195B_DRV_DIS
    #undef CONFIG_8195B
#endif

#define CONFIG_8195B_PKG1
#ifdef CONFIG_8195B_PKG1_DRV_DIS
    #undef CONFIG_8195B_PKG1
#endif

/******************************************************************************
 *                           radioa.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_radioa(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_radioa(void);

/******************************************************************************
 *                           txpowertrack.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_txpowertrack(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_txpowertrack(void);

/******************************************************************************
 *                           txpowertrack_pkg1.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_txpowertrack_pkg1(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_txpowertrack_pkg1(void);

/******************************************************************************
 *                           txpwr_lmt.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_txpwr_lmt(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_txpwr_lmt(void);

/******************************************************************************
 *                           txxtaltrack.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_txxtaltrack(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_txxtaltrack(void);

/******************************************************************************
 *                           txxtaltrack_pkg1.TXT
 ******************************************************************************/

/* tc: Test Chip, mp: mp Chip*/
void
odm_read_and_config_mp_8195b_txxtaltrack_pkg1(struct dm_struct *dm);
u32 odm_get_version_mp_8195b_txxtaltrack_pkg1(void);

#endif
#endif /* end of HWIMG_SUPPORT*/

