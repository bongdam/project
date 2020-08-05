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

/*Image2HeaderVersion: R3 1.5.3*/
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

#if (RTL8710B_SUPPORT == 1)
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

const u32 array_mp_8710b_radioa[] = {
		0x000, 0x00030000,
		0x008, 0x00008400,
		0x017, 0x00000000,
		0x018, 0x00000C01,
		0x019, 0x000739D2,
		0x01C, 0x00000C4C,
		0x01B, 0x00000C6C,
		0x01E, 0x00080009,
		0x01F, 0x00000880,
		0x02F, 0x0001A060,
		0x03F, 0x00015000,
		0x042, 0x000060C0,
		0x057, 0x000D0000,
		0x058, 0x000C0160,
		0x067, 0x00001552,
		0x083, 0x00000000,
		0x0B0, 0x000FF9F0,
		0x0B1, 0x00010018,
		0x0B2, 0x00054C00,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x0B4, 0x000048AB,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x0B4, 0x000048AB,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x0B4, 0x000048AB,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x0B4, 0x000048AB,
	0xA0000000,	0x00000000,
		0x0B4, 0x0004486B,
	0xB0000000,	0x00000000,
		0x0B5, 0x0000112A,
		0x0B6, 0x0000053E,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x0B7, 0x00010408,
		0x0B8, 0x000080C0,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x0B7, 0x00010408,
		0x0B8, 0x000080C0,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x0B7, 0x00010408,
		0x0B8, 0x000080C0,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x0B7, 0x00010408,
		0x0B8, 0x000080C0,
	0xA0000000,	0x00000000,
		0x0B7, 0x00014408,
		0x0B8, 0x00010200,
	0xB0000000,	0x00000000,
		0x0B9, 0x00080801,
		0x0BA, 0x00040001,
		0x0BB, 0x00000400,
		0x0BF, 0x000C0000,
		0x0C2, 0x00002400,
		0x0C3, 0x00000009,
		0x0C4, 0x00040C91,
		0x0C5, 0x00099999,
		0x0C6, 0x000000A3,
		0x0C7, 0x00088820,
		0x0C8, 0x00076C06,
		0x0C9, 0x00000000,
		0x0CA, 0x00080000,
		0x0DF, 0x00000180,
		0x0EF, 0x000001A8,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x03D, 0x00000006,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x03D, 0x00000006,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x03D, 0x00000006,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x03D, 0x00000006,
	0xA0000000,	0x00000000,
		0x03D, 0x00000003,
	0xB0000000,	0x00000000,
		0x03D, 0x00080003,
	0x80001000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x000ED66B,
	0x90004000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x00099F39,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x00099F39,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x00099F39,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x051, 0x00099F39,
	0xA0000000,	0x00000000,
		0x051, 0x000F1E69,
	0xB0000000,	0x00000000,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x052, 0x000FBF64,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x052, 0x000FBF64,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x052, 0x000FBF64,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x052, 0x000FBF64,
	0xA0000000,	0x00000000,
		0x052, 0x000FBF6C,
	0xB0000000,	0x00000000,
		0x053, 0x0000032F,
		0x054, 0x00055007,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x056, 0x000567F0,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x056, 0x000567F0,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x056, 0x000567F0,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x056, 0x000567F0,
	0xA0000000,	0x00000000,
		0x056, 0x000517F0,
	0xB0000000,	0x00000000,
	0x80001000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x00000035,
	0x90004000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000007C,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000007C,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000007C,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000007C,
	0xA0000000,	0x00000000,
		0x035, 0x000000F4,
	0xB0000000,	0x00000000,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000017A,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000017A,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000017A,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000017A,
	0xA0000000,	0x00000000,
		0x035, 0x00000179,
	0xB0000000,	0x00000000,
	0x80001000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x00000235,
		0x036, 0x00000BF6,
		0x036, 0x00008BF6,
		0x036, 0x00010BF6,
		0x036, 0x00018BF6,
	0x90004000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000027C,
		0x036, 0x00000BFC,
		0x036, 0x00008BFC,
		0x036, 0x00010BFC,
		0x036, 0x00018BFC,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000027C,
		0x036, 0x00000BFC,
		0x036, 0x00008BFC,
		0x036, 0x00010BFC,
		0x036, 0x00018BFC,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000027C,
		0x036, 0x00000BFC,
		0x036, 0x00008BFC,
		0x036, 0x00010BFC,
		0x036, 0x00018BFC,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x035, 0x0000027C,
		0x036, 0x00000BFC,
		0x036, 0x00008BFC,
		0x036, 0x00010BFC,
		0x036, 0x00018BFC,
	0xA0000000,	0x00000000,
		0x035, 0x000002F4,
		0x036, 0x00000BF8,
		0x036, 0x00008BF8,
		0x036, 0x00010BF8,
		0x036, 0x00018BF8,
	0xB0000000,	0x00000000,
		0x018, 0x00000C01,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x05A, 0x00068000,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x05A, 0x00068000,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x05A, 0x00068000,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x05A, 0x00068000,
	0xA0000000,	0x00000000,
		0x05A, 0x00048000,
	0xB0000000,	0x00000000,
		0x05A, 0x00048000,
		0x034, 0x0000ADF5,
		0x034, 0x00009DF2,
		0x034, 0x00008DEF,
		0x034, 0x00007DEC,
		0x034, 0x00006DE9,
		0x034, 0x00005CEC,
		0x034, 0x00004CE9,
		0x034, 0x00003C6C,
		0x034, 0x00002C69,
		0x034, 0x0000106E,
		0x034, 0x0000006B,
		0x084, 0x00048000,
		0x087, 0x00000065,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x08E, 0x00065D40,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x08E, 0x00065D40,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x08E, 0x00065D40,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x08E, 0x00065D40,
	0xA0000000,	0x00000000,
		0x08E, 0x00065540,
	0xB0000000,	0x00000000,
		0x0DF, 0x00000110,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x086, 0x0000002F,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x086, 0x0000002F,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x086, 0x0000002F,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x086, 0x0000002F,
	0xA0000000,	0x00000000,
		0x086, 0x0000002A,
	0xB0000000,	0x00000000,
		0x08F, 0x00088000,
		0x081, 0x0003FD80,
		0x0EF, 0x00082000,
		0x03B, 0x000F0F00,
		0x03B, 0x000E0E00,
		0x03B, 0x000DFE00,
		0x03B, 0x000C0D00,
		0x03B, 0x000B0C00,
		0x03B, 0x000A0500,
		0x03B, 0x00090400,
		0x03B, 0x00080000,
		0x03B, 0x00070F00,
		0x03B, 0x00060E00,
	0x80004000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x0005DA00,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x0005DA00,
	0x90006000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x0005DA00,
	0x90007000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x0005DA00,
	0xA0000000,	0x00000000,
		0x03B, 0x00050A00,
	0xB0000000,	0x00000000,
		0x03B, 0x00040D00,
		0x03B, 0x00030C00,
		0x03B, 0x00020500,
		0x03B, 0x00010400,
		0x03B, 0x00000000,
		0x0EF, 0x00080000,
		0x0EF, 0x00080000,
		0x030, 0x00020000,
		0x031, 0x0000000F,
		0x032, 0x00007FF7,
		0x0EF, 0x00000000,
		0x0EF, 0x00080000,
		0x030, 0x00028000,
		0x031, 0x0000000F,
		0x032, 0x000F1173,
		0x0EF, 0x00000000,
		0x0EF, 0x00080000,
		0x030, 0x00030000,
		0x031, 0x0000000F,
		0x032, 0x000F7FF2,
		0x0EF, 0x00000000,
		0x0EF, 0x00088000,
	0x80001000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x000000B0,
	0x90002000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x00000230,
	0x90003000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x00000230,
	0x90005000,	0x00000000,	0x40000000,	0x00000000,
		0x03B, 0x000000B0,
	0xA0000000,	0x00000000,
		0x03B, 0x00000170,
	0xB0000000,	0x00000000,
		0x03B, 0x000C0030,
		0x0EF, 0x00080000,
		0x0EF, 0x00080000,
		0x030, 0x00010000,
		0x031, 0x0000000F,
		0x032, 0x00047EFE,
		0x0EF, 0x00000000,
		0x000, 0x00010159,
		0x018, 0x0000FC01,
		0xFFE, 0x00000000,
		0x000, 0x00033D95,

};

void
odm_read_and_config_mp_8710b_radioa(struct dm_struct *dm)
{
	u32	i = 0;
	u8	c_cond;
	boolean	is_matched = true, is_skipped = false;
	u32	array_len =
			sizeof(array_mp_8710b_radioa) / sizeof(u32);
	u32	*array = (u32 *)array_mp_8710b_radioa;

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
				odm_config_rf_radio_a_8710b(dm, v1, v2);
		}
		i = i + 2;
	}
}

u32
odm_get_version_mp_8710b_radioa(void)
{
		return 18;
}

/******************************************************************************
 *                           txpowertrack_qfn48m_smic.TXT
 ******************************************************************************/

#ifdef CONFIG_8710B_QFN48M_SMIC
const u8 delta_swingidx_mp_2gb_n_txpwrtrk_qfn48m_smic_8710b[]    = {
	0, 0, 0, 2, 2, 3, 3, 4, 4, 4, 4, 5, 5, 6, 6, 7, 7,
	 7, 7, 8, 8, 9, 9, 10, 10, 10, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2gb_p_txpwrtrk_qfn48m_smic_8710b[]    = {
	0, 0, 0, 1, 2, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 9, 9,
	 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2ga_n_txpwrtrk_qfn48m_smic_8710b[]    = {
	0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7,
	 7, 8, 8, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10};
const u8 delta_swingidx_mp_2ga_p_txpwrtrk_qfn48m_smic_8710b[]    = {
	0, 0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6,
	 6, 6, 7, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9};
const u8 delta_swingidx_mp_2g_cck_b_n_txpwrtrk_qfn48m_smic_8710b[] = {
	0, 0, 1, 1, 2, 4, 4, 5, 5, 6, 7, 7, 7, 8, 8, 9, 10, 10,
	 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12};
const u8 delta_swingidx_mp_2g_cck_b_p_txpwrtrk_qfn48m_smic_8710b[] = {
	0, 0, 1, 1, 2, 2, 2, 3, 4, 5, 6, 6, 7, 7, 8, 9, 9, 10,
	 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2g_cck_a_n_txpwrtrk_qfn48m_smic_8710b[] = {
	0, 0, 1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6,
	 7, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
const u8 delta_swingidx_mp_2g_cck_a_p_txpwrtrk_qfn48m_smic_8710b[] = {
	0, 0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 6, 6, 6,
	 7, 7, 8, 9, 10, 12, 12, 12, 12, 12, 12, 12, 12};
#endif

void
odm_read_and_config_mp_8710b_txpowertrack_qfn48m_smic(struct dm_struct *dm)
{
#ifdef CONFIG_8710B_QFN48M_SMIC

struct dm_rf_calibration_struct  *cali_info = &dm->rf_calibrate_info;

PHYDM_DBG(dm, ODM_COMP_INIT, "===> ODM_ReadAndConfig_MP_mp_8710b\n");

odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_p,
		(void *)delta_swingidx_mp_2ga_p_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_n,
		(void *)delta_swingidx_mp_2ga_n_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2gb_p,
		(void *)delta_swingidx_mp_2gb_p_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2gb_n,
		(void *)delta_swingidx_mp_2gb_n_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);

odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_p,
		(void *)delta_swingidx_mp_2g_cck_a_p_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_n,
		(void *)delta_swingidx_mp_2g_cck_a_n_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_b_p,
		(void *)delta_swingidx_mp_2g_cck_b_p_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_b_n,
		(void *)delta_swingidx_mp_2g_cck_b_n_txpwrtrk_qfn48m_smic_8710b,
		DELTA_SWINGIDX_SIZE);
#endif
}

/******************************************************************************
 *                           txpowertrack_qfn48m_umc.TXT
 ******************************************************************************/

#ifdef CONFIG_8710B_QFN48M_UMC
const u8 delta_swingidx_mp_2gb_n_txpwrtrk_qfn48m_umc_8710b[]    = {
	0, 0, 0, 2, 2, 3, 3, 4, 4, 4, 4, 5, 5, 6, 6, 7, 7,
	 7, 7, 8, 8, 9, 9, 10, 10, 10, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2gb_p_txpwrtrk_qfn48m_umc_8710b[]    = {
	0, 0, 0, 1, 2, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 9, 9,
	 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2ga_n_txpwrtrk_qfn48m_umc_8710b[]    = {
	0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7,
	 7, 8, 8, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10};
const u8 delta_swingidx_mp_2ga_p_txpwrtrk_qfn48m_umc_8710b[]    = {
	0, 0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6,
	 6, 6, 7, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9};
const u8 delta_swingidx_mp_2g_cck_b_n_txpwrtrk_qfn48m_umc_8710b[] = {
	0, 0, 1, 1, 2, 4, 4, 5, 5, 6, 7, 7, 7, 8, 8, 9, 10, 10,
	 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12};
const u8 delta_swingidx_mp_2g_cck_b_p_txpwrtrk_qfn48m_umc_8710b[] = {
	0, 0, 1, 1, 2, 2, 2, 3, 4, 5, 6, 6, 7, 7, 8, 9, 9, 10,
	 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11};
const u8 delta_swingidx_mp_2g_cck_a_n_txpwrtrk_qfn48m_umc_8710b[] = {
	0, 0, 1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6,
	 7, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
const u8 delta_swingidx_mp_2g_cck_a_p_txpwrtrk_qfn48m_umc_8710b[] = {
	0, 0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 6, 6, 6,
	 7, 7, 8, 9, 10, 12, 12, 12, 12, 12, 12, 12, 12};
#endif

void
odm_read_and_config_mp_8710b_txpowertrack_qfn48m_umc(struct dm_struct *dm)
{
#ifdef CONFIG_8710B_QFN48M_UMC

struct dm_rf_calibration_struct  *cali_info = &dm->rf_calibrate_info;

PHYDM_DBG(dm, ODM_COMP_INIT, "===> ODM_ReadAndConfig_MP_mp_8710b\n");

odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_p,
		(void *)delta_swingidx_mp_2ga_p_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2ga_n,
		(void *)delta_swingidx_mp_2ga_n_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2gb_p,
		(void *)delta_swingidx_mp_2gb_p_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2gb_n,
		(void *)delta_swingidx_mp_2gb_n_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);

odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_p,
		(void *)delta_swingidx_mp_2g_cck_a_p_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_a_n,
		(void *)delta_swingidx_mp_2g_cck_a_n_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_b_p,
		(void *)delta_swingidx_mp_2g_cck_b_p_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
odm_move_memory(dm, cali_info->delta_swing_table_idx_2g_cck_b_n,
		(void *)delta_swingidx_mp_2g_cck_b_n_txpwrtrk_qfn48m_umc_8710b,
		DELTA_SWINGIDX_SIZE);
#endif
}

/******************************************************************************
 *                           txpwr_lmt.TXT
 ******************************************************************************/

#ifdef CONFIG_8710B
const char *array_mp_8710b_txpwr_lmt[] = {
	"FCC", "2.4G", "20M", "CCK", "1T", "01", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "01", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "01", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "02", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "02", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "02", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "03", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "03", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "03", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "04", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "04", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "04", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "05", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "05", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "05", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "06", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "06", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "06", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "07", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "07", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "07", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "08", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "08", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "08", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "09", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "09", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "09", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "10", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "10", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "10", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "11", "32",
	"ETSI", "2.4G", "20M", "CCK", "1T", "11", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "11", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "12", "30",
	"ETSI", "2.4G", "20M", "CCK", "1T", "12", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "12", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "13", "10",
	"ETSI", "2.4G", "20M", "CCK", "1T", "13", "28",
	"MKK", "2.4G", "20M", "CCK", "1T", "13", "32",
	"FCC", "2.4G", "20M", "CCK", "1T", "14", "63",
	"ETSI", "2.4G", "20M", "CCK", "1T", "14", "63",
	"MKK", "2.4G", "20M", "CCK", "1T", "14", "32",
	"FCC", "2.4G", "20M", "OFDM", "1T", "01", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "01", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "01", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "02", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "02", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "02", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "03", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "03", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "03", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "04", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "04", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "04", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "05", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "05", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "05", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "06", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "06", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "06", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "07", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "07", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "07", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "08", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "08", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "08", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "09", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "09", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "09", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "10", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "10", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "10", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "11", "30",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "11", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "11", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "12", "26",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "12", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "12", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "13", "12",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "13", "30",
	"MKK", "2.4G", "20M", "OFDM", "1T", "13", "30",
	"FCC", "2.4G", "20M", "OFDM", "1T", "14", "63",
	"ETSI", "2.4G", "20M", "OFDM", "1T", "14", "63",
	"MKK", "2.4G", "20M", "OFDM", "1T", "14", "63",
	"FCC", "2.4G", "20M", "HT", "1T", "01", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "01", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "01", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "02", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "02", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "02", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "03", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "03", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "03", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "04", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "04", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "04", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "05", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "05", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "05", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "06", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "06", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "06", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "07", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "07", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "07", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "08", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "08", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "08", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "09", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "09", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "09", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "10", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "10", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "10", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "11", "30",
	"ETSI", "2.4G", "20M", "HT", "1T", "11", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "11", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "12", "26",
	"ETSI", "2.4G", "20M", "HT", "1T", "12", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "12", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "13", "8",
	"ETSI", "2.4G", "20M", "HT", "1T", "13", "30",
	"MKK", "2.4G", "20M", "HT", "1T", "13", "30",
	"FCC", "2.4G", "20M", "HT", "1T", "14", "63",
	"ETSI", "2.4G", "20M", "HT", "1T", "14", "63",
	"MKK", "2.4G", "20M", "HT", "1T", "14", "63",
	"FCC", "2.4G", "40M", "HT", "1T", "01", "63",
	"ETSI", "2.4G", "40M", "HT", "1T", "01", "63",
	"MKK", "2.4G", "40M", "HT", "1T", "01", "63",
	"FCC", "2.4G", "40M", "HT", "1T", "02", "63",
	"ETSI", "2.4G", "40M", "HT", "1T", "02", "63",
	"MKK", "2.4G", "40M", "HT", "1T", "02", "63",
	"FCC", "2.4G", "40M", "HT", "1T", "03", "28",
	"ETSI", "2.4G", "40M", "HT", "1T", "03", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "03", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "04", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "04", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "04", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "05", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "05", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "05", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "06", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "06", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "06", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "07", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "07", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "07", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "08", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "08", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "08", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "09", "30",
	"ETSI", "2.4G", "40M", "HT", "1T", "09", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "09", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "10", "28",
	"ETSI", "2.4G", "40M", "HT", "1T", "10", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "10", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "11", "26",
	"ETSI", "2.4G", "40M", "HT", "1T", "11", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "11", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "12", "63",
	"ETSI", "2.4G", "40M", "HT", "1T", "12", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "12", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "13", "63",
	"ETSI", "2.4G", "40M", "HT", "1T", "13", "26",
	"MKK", "2.4G", "40M", "HT", "1T", "13", "26",
	"FCC", "2.4G", "40M", "HT", "1T", "14", "63",
	"ETSI", "2.4G", "40M", "HT", "1T", "14", "63",
	"MKK", "2.4G", "40M", "HT", "1T", "14", "63"
};
#endif

void
odm_read_and_config_mp_8710b_txpwr_lmt(struct dm_struct *dm)
{
#ifdef CONFIG_8710B

	u32	i = 0;
#if (DM_ODM_SUPPORT_TYPE == ODM_IOT)
	u32	array_len =
			sizeof(array_mp_8710b_txpwr_lmt) / sizeof(u8);
	u8	*array = (u8 *)array_mp_8710b_txpwr_lmt;
#else
	u32	array_len =
			sizeof(array_mp_8710b_txpwr_lmt) / sizeof(u8 *);
	u8	**array = (u8 **)array_mp_8710b_txpwr_lmt;
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

		odm_config_bb_txpwr_lmt_8710b(dm, regulation, band, bandwidth,
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

const s8 delta_swing_xtal_mp_n_txxtaltrack_8710b[]    = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const s8 delta_swing_xtal_mp_p_txxtaltrack_8710b[]    = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, -5, -12, -18, -27, -28, -32, -32};

void
odm_read_and_config_mp_8710b_txxtaltrack(struct dm_struct *dm)
{
	struct dm_rf_calibration_struct	*cali_info = &dm->rf_calibrate_info;

	PHYDM_DBG(dm, ODM_COMP_INIT, "===> ODM_ReadAndConfig_MP_mp_8710b\n");

	odm_move_memory(dm, cali_info->delta_swing_table_xtal_p,
			(void *)delta_swing_xtal_mp_p_txxtaltrack_8710b,
			DELTA_SWINGIDX_SIZE);
	odm_move_memory(dm, cali_info->delta_swing_table_xtal_n,
			(void *)delta_swing_xtal_mp_n_txxtaltrack_8710b,
			DELTA_SWINGIDX_SIZE);
}

#endif /* end of HWIMG_SUPPORT*/

