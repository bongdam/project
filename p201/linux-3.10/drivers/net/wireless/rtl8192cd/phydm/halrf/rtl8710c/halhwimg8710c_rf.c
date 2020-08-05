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

/*Image2HeaderVersion: R3 1.5.7*/
#include "mp_precomp.h"

#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#define D_S_SIZE DELTA_SWINGIDX_SIZE
#define D_ST_SIZE DELTA_SWINTSSI_SIZE

#if (RTL8710C_SUPPORT == 1)
static boolean
check_positive(struct dm_struct *dm,
	       const u32	condition1,
	       const u32	condition2,
	       const u32	condition3,
	       const u32	condition4
)
{
	u32	cond1 = condition1, cond2 = condition2,
		cond3 = condition3, cond4 = condition4;

	u8	cut_version_for_para =
		(dm->cut_version ==  ODM_CUT_A) ? 15 : dm->cut_version;

	u8	pkg_type_for_para =
		(dm->package_type == 0) ? 15 : dm->package_type;

	u32	driver1 = cut_version_for_para << 24 |
			(dm->support_interface & 0xF0) << 16 |
			dm->support_platform << 16 |
			pkg_type_for_para << 12 |
			(dm->support_interface & 0x0F) << 8  |
			dm->rfe_type;

	u32	driver2 = (dm->type_glna & 0xFF) <<  0 |
			(dm->type_gpa & 0xFF)  <<  8 |
			(dm->type_alna & 0xFF) << 16 |
			(dm->type_apa & 0xFF)  << 24;

	u32	driver3 = 0;

	u32	driver4 = (dm->type_glna & 0xFF00) >>  8 |
			(dm->type_gpa & 0xFF00) |
			(dm->type_alna & 0xFF00) << 8 |
			(dm->type_apa & 0xFF00)  << 16;

	PHYDM_DBG(dm, ODM_COMP_INIT,
		  "===> %s (cond1, cond2, cond3, cond4) = (0x%X 0x%X 0x%X 0x%X)\n",
		  __func__, cond1, cond2, cond3, cond4);
	PHYDM_DBG(dm, ODM_COMP_INIT,
		  "===> %s (driver1, driver2, driver3, driver4) = (0x%X 0x%X 0x%X 0x%X)\n",
		  __func__, driver1, driver2, driver3, driver4);

	PHYDM_DBG(dm, ODM_COMP_INIT,
		  "	(Platform, Interface) = (0x%X, 0x%X)\n",
		  dm->support_platform, dm->support_interface);
	PHYDM_DBG(dm, ODM_COMP_INIT, "	(RFE, Package) = (0x%X, 0x%X)\n",
		  dm->rfe_type, dm->package_type);

	/*============== value Defined Check ===============*/
	/*cut version [27:24] need to do value check*/
	if (((cond1 & 0x0F000000) != 0) &&
	    ((cond1 & 0x0F000000) != (driver1 & 0x0F000000)))
		return false;

	/*pkg type [15:12] need to do value check*/
	if (((cond1 & 0x0000F000) != 0) &&
	    ((cond1 & 0x0000F000) != (driver1 & 0x0000F000)))
		return false;

	/*interface [11:8] need to do value check*/
	if (((cond1 & 0x00000F00) != 0) &&
	    ((cond1 & 0x00000F00) != (driver1 & 0x00000F00)))
		return false;
	/*=============== Bit Defined Check ================*/
	/* We don't care [31:28] */

	cond1 &= 0x000000FF;
	driver1 &= 0x000000FF;

	if (cond1 == driver1)
		return true;
	else
		return false;
}


/******************************************************************************
 *                           radioa.TXT
 ******************************************************************************/

const u32 array_mp_8710c_radioa[] = {
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x020, 0x00040800,
		0x00F, 0x00000003,
	0xA0000000,	0x00000000,
		0x00F, 0x00000033,
	0xB0000000,	0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00000001,
		0x033, 0x00000000,
		0x03F, 0x00008727,
		0x033, 0x00000001,
		0x03F, 0x00008727,
		0x033, 0x00000002,
		0x03F, 0x00008727,
		0x033, 0x00000003,
		0x03F, 0x00008727,
		0x033, 0x00000004,
		0x03F, 0x00008727,
		0x033, 0x00000005,
		0x03F, 0x00008727,
		0x033, 0x00000006,
		0x03F, 0x00008727,
		0x033, 0x00000007,
		0x03F, 0x00008727,
		0x033, 0x00000008,
		0x03F, 0x00008727,
		0x033, 0x00000009,
		0x03F, 0x00008727,
		0x033, 0x0000000A,
		0x03F, 0x00008727,
		0x033, 0x0000000B,
		0x03F, 0x00008727,
		0x033, 0x0000000C,
		0x03F, 0x00008727,
		0x033, 0x0000000D,
		0x03F, 0x00008727,
		0x033, 0x0000000E,
		0x03F, 0x00008727,
		0x033, 0x0000000F,
		0x03F, 0x00008727,
		0x033, 0x00000010,
		0x03F, 0x00008727,
		0x033, 0x00000011,
		0x03F, 0x00008727,
		0x033, 0x00000012,
		0x03F, 0x00008727,
		0x033, 0x00000013,
		0x03F, 0x00008727,
		0x033, 0x00000014,
		0x03F, 0x00008727,
		0x033, 0x00000015,
		0x03F, 0x00008727,
		0x033, 0x00000016,
		0x03F, 0x00008727,
		0x033, 0x00000017,
		0x03F, 0x00008727,
		0x033, 0x00000018,
		0x03F, 0x00008727,
		0x033, 0x00000019,
		0x03F, 0x00008727,
		0x033, 0x0000001A,
		0x03F, 0x00008727,
		0x033, 0x0000001B,
		0x03F, 0x00008727,
		0x033, 0x0000001C,
		0x03F, 0x00008727,
		0x033, 0x0000001D,
		0x03F, 0x00008727,
		0x033, 0x0000001E,
		0x03F, 0x00008727,
		0x033, 0x0000001F,
		0x03F, 0x00008727,
		0x0EF, 0x00000000,
		0x0AA, 0x000024FA,
		0x0DE, 0x000000F9,
		0x080, 0x0000000D,
		0x0EF, 0x00000040,
		0x033, 0x00000000,
		0x03D, 0x000002F2,
		0x03E, 0x00018C00,
		0x03F, 0x0000A400,
		0x033, 0x00000001,
		0x03D, 0x000002F2,
		0x03E, 0x00018C00,
		0x03F, 0x0000A400,
		0x0EF, 0x00000000,
	0xA0000000,	0x00000000,
	0xB0000000,	0x00000000,
		0x0EF, 0x00001000,
		0x033, 0x00000000,
		0x03F, 0x00000AD5,
		0x033, 0x00000001,
		0x03F, 0x00000AD5,
		0x033, 0x00000002,
		0x03F, 0x00000AD5,
		0x033, 0x00000004,
		0x03F, 0x00000255,
		0x033, 0x00000005,
		0x03F, 0x00000255,
		0x033, 0x00000006,
		0x03F, 0x00000255,
		0x033, 0x00000008,
		0x03F, 0x00000A55,
		0x033, 0x00000009,
		0x03F, 0x00000855,
		0x033, 0x0000000A,
		0x03F, 0x00000855,
		0x033, 0x0000000B,
		0x03F, 0x00000855,
		0x033, 0x0000000C,
		0x03F, 0x00000855,
		0x033, 0x0000000D,
		0x03F, 0x00000855,
		0x0EF, 0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x000A97F3,
		0x052, 0x0002A180,
	0xA0000000,	0x00000000,
		0x051, 0x000A99F3,
		0x052, 0x0002A180,
	0xB0000000,	0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00000004,
		0x033, 0x00000011,
		0x03F, 0x00008674,
		0x033, 0x0000001B,
		0x03F, 0x00009674,
		0x033, 0x0000001C,
		0x03F, 0x00008674,
		0x033, 0x00000003,
		0x03F, 0x00008674,
		0x033, 0x00000009,
		0x03F, 0x00008674,
		0x033, 0x0000000A,
		0x03F, 0x00009674,
		0x0EF, 0x00000000,
	0xA0000000,	0x00000000,
		0x0EF, 0x00000004,
		0x033, 0x00000011,
		0x03F, 0x00008694,
		0x033, 0x0000001B,
		0x03F, 0x00008794,
		0x033, 0x0000001C,
		0x03F, 0x00008694,
		0x033, 0x00000003,
		0x03F, 0x00008694,
		0x033, 0x00000009,
		0x03F, 0x00008694,
		0x033, 0x0000000A,
		0x03F, 0x00009794,
		0x0EF, 0x00000000,
	0xB0000000,	0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00000002,
		0x033, 0x00000000,
		0x03F, 0x0000042C,
		0x033, 0x00000001,
		0x03F, 0x00000667,
		0x033, 0x00000002,
		0x03F, 0x0000066A,
		0x033, 0x00000003,
		0x03F, 0x000006A9,
		0x033, 0x00000004,
		0x03F, 0x000006AC,
		0x033, 0x00000005,
		0x03F, 0x00000ACB,
		0x033, 0x00000006,
		0x03F, 0x00000ACE,
		0x033, 0x00000007,
		0x03F, 0x00000EEE,
		0x033, 0x00000008,
		0x03F, 0x00000EF1,
		0x033, 0x00000009,
		0x03F, 0x00000EF4,
		0x033, 0x0000000A,
		0x03F, 0x00000EF7,
		0x033, 0x00000010,
		0x03F, 0x0000042C,
		0x033, 0x00000011,
		0x03F, 0x00000667,
		0x033, 0x00000012,
		0x03F, 0x0000066A,
		0x033, 0x00000013,
		0x03F, 0x000006A9,
		0x033, 0x00000014,
		0x03F, 0x000006AC,
		0x033, 0x00000015,
		0x03F, 0x00000ACB,
		0x033, 0x00000016,
		0x03F, 0x00000ACE,
		0x033, 0x00000017,
		0x03F, 0x00000EEE,
		0x033, 0x00000018,
		0x03F, 0x00000EF1,
		0x033, 0x00000019,
		0x03F, 0x00000EF4,
		0x033, 0x0000001A,
		0x03F, 0x00000EF7,
		0x0EF, 0x00000000,
	0xA0000000,	0x00000000,
		0x0EF, 0x00000002,
		0x033, 0x00000000,
		0x03F, 0x0000062A,
		0x033, 0x00000001,
		0x03F, 0x00000A47,
		0x033, 0x00000002,
		0x03F, 0x00000A4A,
		0x033, 0x00000003,
		0x03F, 0x00000A4D,
		0x033, 0x00000004,
		0x03F, 0x00000C4F,
		0x033, 0x00000005,
		0x03F, 0x00000EAB,
		0x033, 0x00000006,
		0x03F, 0x00000EEB,
		0x033, 0x00000007,
		0x03F, 0x00000EEE,
		0x033, 0x00000008,
		0x03F, 0x00000EF1,
		0x033, 0x00000009,
		0x03F, 0x00000EF4,
		0x033, 0x0000000A,
		0x03F, 0x00000EF7,
		0x033, 0x00000010,
		0x03F, 0x0000062A,
		0x033, 0x00000011,
		0x03F, 0x00000A47,
		0x033, 0x00000012,
		0x03F, 0x00000A4A,
		0x033, 0x00000013,
		0x03F, 0x00000A4D,
		0x033, 0x00000014,
		0x03F, 0x00000C4F,
		0x033, 0x00000015,
		0x03F, 0x00000EAB,
		0x033, 0x00000016,
		0x03F, 0x00000EEB,
		0x033, 0x00000017,
		0x03F, 0x00000EEE,
		0x033, 0x00000018,
		0x03F, 0x00000EF1,
		0x033, 0x00000019,
		0x03F, 0x00000EF4,
		0x033, 0x0000001A,
		0x03F, 0x00000EF7,
		0x0EF, 0x00000000,
	0xB0000000,	0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x08F, 0x000B0018,
		0x086, 0x000CC049,
		0x087, 0x000B1081,
		0x088, 0x00011848,
	0xA0000000,	0x00000000,
	0xB0000000,	0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00000100,
		0x033, 0x00000000,
		0x03F, 0x0000041B,
		0x0EF, 0x00000000,
	0xA0000000,	0x00000000,
	0xB0000000,	0x00000000,
		0x0EF, 0x00000200,
		0x033, 0x00000000,
		0x03E, 0x0000000A,
		0x03F, 0x00062122,
		0x0EF, 0x00000000,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00000200,
		0x033, 0x00000001,
		0x03E, 0x0000001F,
		0x03F, 0x000E1D1A,
		0x033, 0x00000002,
		0x03E, 0x0000001F,
		0x03F, 0x000E1D1A,
		0x033, 0x00000003,
		0x03E, 0x0000001F,
		0x03F, 0x000E1D1A,
		0x033, 0x00000004,
		0x03E, 0x0000001F,
		0x03F, 0x000E1D1A,
		0x0EF, 0x00000000,
		0x0A7, 0x00008080,
		0x0AD, 0x00030401,
		0x0A9, 0x00003781,
		0x0BF, 0x000F0000,
		0x0C0, 0x00080000,
		0x0BB, 0x000781C4,
		0x0BC, 0x00080001,
	0xA0000000,	0x00000000,
	0xB0000000,	0x00000000,
		0x01C, 0x00000100,
		0x01B, 0x00000200,
		0x01B, 0x00000240,
	0x8f000000,	0x00000000,	0x40000000,	0x00000000,
		0x0EF, 0x00004000,
		0x033, 0x0000000C,
		0x03F, 0x00000022,
		0x0EF, 0x00000000,
		0x0EF, 0x00004000,
		0x033, 0x00000003,
		0x03F, 0x00000022,
		0x0EF, 0x00000000,
		0x0EF, 0x00004000,
		0x033, 0x00000021,
		0x03F, 0x00000023,
		0x033, 0x0000001F,
		0x03F, 0x00000021,
		0x0EF, 0x00000000,
		0x0EF, 0x00008000,
		0x030, 0x0000000A,
		0x0EF, 0x00000000,
		0x0EF, 0x00002000,
		0x030, 0x00000003,
		0x030, 0x00001003,
		0x030, 0x00002003,
		0x0EF, 0x00000000,
		0x0EF, 0x00001000,
		0x033, 0x00000000,
		0x03F, 0x00000A55,
		0x0EF, 0x00000000,
		0x0EF, 0x00080000,
		0x033, 0x00000007,
		0x03E, 0x000001D1,
		0x03F, 0x000EA7F7,
		0x0EF, 0x00080000,
		0x033, 0x00000014,
		0x03E, 0x000003C1,
		0x03F, 0x0000B3AA,
		0x0EF, 0x00000000,
		0x0EF, 0x00000000,
		0x0EF, 0x00010000,
		0x033, 0x00000003,
		0x03F, 0x0000608A,
		0x033, 0x0000000B,
		0x03F, 0x0000608A,
		0x033, 0x00000013,
		0x03F, 0x0000608A,
		0x033, 0x0000001B,
		0x03F, 0x0000608A,
		0x033, 0x00000023,
		0x03F, 0x0000608A,
		0x033, 0x0000002B,
		0x03F, 0x0000608A,
		0x033, 0x00000033,
		0x03F, 0x0000608A,
		0x0EF, 0x00000000,
	0xA0000000,	0x00000000,
		0x0EF, 0x00080000,
		0x033, 0x00000014,
		0x03E, 0x000003C1,
		0x03F, 0x0000B3AA,
		0x0EF, 0x00000000,
	0xB0000000,	0x00000000,
		0x01D, 0x00000009,
		0x018, 0x00008C01,
		0xFFE, 0x00000000,
		0x0EF, 0x00000020,
		0x030, 0x000010C0,
		0x030, 0x000000C0,
		0x0EF, 0x00000000,
		0x088, 0x00030800,

};

void
odm_read_and_config_mp_8710c_radioa(struct dm_struct *dm)
{
	u32	i = 0;
	u8	c_cond;
	boolean	is_matched = true, is_skipped = false;
	u32	array_len =
			sizeof(array_mp_8710c_radioa) / sizeof(u32);
	u32	*array = (u32 *)array_mp_8710c_radioa;

	u32	v1 = 0, v2 = 0, pre_v1 = 0, pre_v2 = 0;
	u32	a1 = 0, a2 = 0, a3 = 0, a4 = 0;

	PHYDM_DBG(dm, ODM_COMP_INIT, "===> %s\n", __func__);

	while ((i + 1) < array_len) {
		v1 = array[i];
		v2 = array[i + 1];

		if (v1 & (BIT(31) | BIT(30))) {/*positive & negative condition*/
			if (v1 & BIT(31)) {/* positive condition*/
				c_cond  =
					(u8)((v1 & (BIT(29) | BIT(28))) >> 28);
				if (c_cond == COND_ENDIF) {/*end*/
					is_matched = true;
					is_skipped = false;
					PHYDM_DBG(dm, ODM_COMP_INIT, "ENDIF\n");
				} else if (c_cond == COND_ELSE) { /*else*/
					is_matched = is_skipped ? false : true;
					PHYDM_DBG(dm, ODM_COMP_INIT, "ELSE\n");
				} else {/*if , else if*/
					pre_v1 = v1;
					pre_v2 = v2;
					PHYDM_DBG(dm, ODM_COMP_INIT,
						  "IF or ELSE IF\n");
				}
			} else if (v1 & BIT(30)) { /*negative condition*/
				if (!is_skipped) {
					a1 = pre_v1; a2 = pre_v2;
					a3 = v1; a4 = v2;
					if (check_positive(dm,
							   a1, a2, a3, a4)) {
						is_matched = true;
						is_skipped = true;
					} else {
						is_matched = false;
						is_skipped = false;
					}
				} else {
					is_matched = false;
				}
			}
		} else {
			if (is_matched)
				odm_config_rf_radio_a_8710c(dm, v1, v2);
		}
		i = i + 2;
	}
}

u32
odm_get_version_mp_8710c_radioa(void)
{
		return 5;
}

/******************************************************************************
 *                           txpowertrack.TXT
 ******************************************************************************/

#ifdef CONFIG_8710C
const s8 delta_swingidx_mp_2ga_n_txpwrtrk_8710c[]    = {
	0, 1, 2, 2, 3, 3, 4, 5, 5, 6, 6, 6, 6, 7, 7, 8, 9, 9,
	 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15};
const s8 delta_swingidx_mp_2ga_p_txpwrtrk_8710c[]    = {
	0, 0, 1, 1, 2, 3, 3, 3, 4, 4, 5, 6, 7, 8, 9, 9, 9, 10,
	 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16};
const s8 delta_swingidx_mp_2g_cck_a_n_txpwrtrk_8710c[] = {
	0, 1, 2, 2, 3, 3, 4, 4, 4, 5, 6, 7, 7, 8, 8, 9, 9, 9,
	 10, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15};
const s8 delta_swingidx_mp_2g_cck_a_p_txpwrtrk_8710c[] = {
	0, 0, 1, 1, 2, 2, 3, 3, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9,
	 10, 10, 11, 12, 13, 13, 14, 14, 15, 15, 16, 16};
#endif

void
odm_read_and_config_mp_8710c_txpowertrack(struct dm_struct *dm)
{
#ifdef CONFIG_8710C

struct dm_rf_calibration_struct  *cali_info = &dm->rf_calibrate_info;

PHYDM_DBG(dm, ODM_COMP_INIT, "===> ODM_ReadAndConfig_MP_mp_8710c\n");

odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_p,
		(void *)delta_swingidx_mp_2ga_p_txpwrtrk_8710c,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_n,
		(void *)delta_swingidx_mp_2ga_n_txpwrtrk_8710c,
		DELTA_SWINGIDX_SIZE);

odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_p,
		(void *)delta_swingidx_mp_2g_cck_a_p_txpwrtrk_8710c,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_n,
		(void *)delta_swingidx_mp_2g_cck_a_n_txpwrtrk_8710c,
		DELTA_SWINGIDX_SIZE);
#endif
}

/******************************************************************************
 *                           txpwr_lmt.TXT
 ******************************************************************************/

#ifdef CONFIG_8710C
_WEAK const u8 array_mp_8710c_txpwr_lmt[] = {
	/* regulation, band, bandwidth, rateSection, rfPath, chnl, value */
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	1,	38,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	2,	38,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	3,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	4,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	5,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	6,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	7,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	8,	42,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	9,	36,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	10,	36,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	11,	36,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	12,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	13,	10,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_CCK,	PW_LMT_PH_1T,	14,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	3,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	4,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	5,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	6,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	7,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	8,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	9,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	10,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	11,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	12,	26,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	13,	12,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_OFDM,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	40,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	26,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	8,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	32,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_20M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	1,	63,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	2,	63,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	28,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	3,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	4,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	5,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	6,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	7,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	8,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	30,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	9,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	28,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	10,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	26,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	11,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	12,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	26,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	13,	26,
	PW_LMT_REGU_FCC,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_ETSI,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63,
	PW_LMT_REGU_MKK,	PW_LMT_BAND_2_4G,	PW_LMT_BW_40M,	PW_LMT_RS_HT,	PW_LMT_PH_1T,	14,	63
};
#endif

void
odm_read_and_config_mp_8710c_txpwr_lmt(struct dm_struct *dm)
{
#ifdef CONFIG_8710C

	u32	i = 0;
#if (DM_ODM_SUPPORT_TYPE == ODM_IOT)
	u32	array_len =
			sizeof(array_mp_8710c_txpwr_lmt) / sizeof(u8);
	u8	*array = (u8 *)array_mp_8710c_txpwr_lmt;
#else
	u32	array_len =
			sizeof(array_mp_8710c_txpwr_lmt) / sizeof(u8 *);
	u8	**array = (u8 **)array_mp_8710c_txpwr_lmt;
#endif

#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
	void	*adapter = dm->adapter;
	HAL_DATA_TYPE	*hal_data = GET_HAL_DATA(((PADAPTER)adapter));

	odm_memory_set(dm, hal_data->BufOfLinesPwrLmt, 0,
		       MAX_LINES_HWCONFIG_TXT *
		       MAX_BYTES_LINE_HWCONFIG_TXT);
	hal_data->nLinesReadPwrLmt = array_len / 7;
#endif

	PHYDM_DBG(dm, ODM_COMP_INIT, "===> %s\n", __func__);

	for (i = 0; i < array_len; i += 7) {
#if (DM_ODM_SUPPORT_TYPE == ODM_IOT)
		u8	regulation = array[i];
		u8	band = array[i + 1];
		u8	bandwidth = array[i + 2];
		u8	rate = array[i + 3];
		u8	rf_path = array[i + 4];
		u8	chnl = array[i + 5];
		u8	val = array[i + 6];
#else
		u8	*regulation = array[i];
		u8	*band = array[i + 1];
		u8	*bandwidth = array[i + 2];
		u8	*rate = array[i + 3];
		u8	*rf_path = array[i + 4];
		u8	*chnl = array[i + 5];
		u8	*val = array[i + 6];
#endif

		odm_config_bb_txpwr_lmt_8710c(dm, regulation, band, bandwidth,
					      rate, rf_path, chnl, val);
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
		rsprintf((char *)hal_data->BufOfLinesPwrLmt[i / 7], 100, "\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\",",
			 regulation, band, bandwidth, rate, rf_path, chnl, val);
#endif
	}

#endif
}

/******************************************************************************
 *                           txxtaltrack.TXT
 ******************************************************************************/

const s8 delta_swing_xtal_mp_n_txxtaltrack_8710c[]    = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const s8 delta_swing_xtal_mp_p_txxtaltrack_8710c[]    = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -6, -6, -6, -6,
	 -6, -12, -16, -16, -16, -20, -20, -20, -20, -20, -20};

void
odm_read_and_config_mp_8710c_txxtaltrack(struct dm_struct *dm)
{
	struct dm_rf_calibration_struct	*cali_info = &dm->rf_calibrate_info;

	PHYDM_DBG(dm, ODM_COMP_INIT, "===> ODM_ReadAndConfig_MP_mp_8710c\n");

	odm_move_memory(dm, cali_info->delta_swing_table_xtal_p,
			(void *)delta_swing_xtal_mp_p_txxtaltrack_8710c,
			DELTA_SWINGIDX_SIZE);
	odm_move_memory(dm, cali_info->delta_swing_table_xtal_n,
			(void *)delta_swing_xtal_mp_n_txxtaltrack_8710c,
			DELTA_SWINGIDX_SIZE);
}

#endif /* end of HWIMG_SUPPORT*/

