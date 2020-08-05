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

#if (RTL8814B_SUPPORT == 1)

/*---------------------------Define Local Constant---------------------------*/

/*8814B DPK ver:0x1 20180820*/
static  boolean rf_56_txbb_flag = false;

boolean
_dpk_check_nctl_done_8814b(struct dm_struct *dm, u8 path, u32 IQK_CMD)
{
	/*this function is only used after the version of nctl8.0*/
	boolean notready = true;
	boolean fail = true;
	u32 delay_count = 0x0;

	while (notready) {
		if (odm_read_1byte(dm, 0x2d9c) == 0x55)
			notready = false;
		else
			notready = true;

		if (notready) {
			/*ODM_sleep_ms(1);*/
			ODM_delay_us(50);
			delay_count++;
		} else {
			fail = (boolean)odm_get_bb_reg(dm, 0x1b08, BIT(26));
			break;
		}
		if (delay_count >= 100) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK]S%d DPK timeout!!!\n",
			       path);
			break;
		}
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	odm_write_1byte(dm, 0x2d9c, 0x0);
	return fail;
}


boolean
_dpk_deb_log_8814b(struct dm_struct *dm)
{
	u8 path = 0x0;
	u8 i;

#if 1
	for (path = 0x3; path < SS_8814B; path++) {
		odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
		for (i = 0; i <  0x100/4; i++)
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d 1b%x = 0x%x\n", path, i*4, odm_read_4byte(dm, (0x1b00 + i*4)));
		for (i = 0; i <  0xfe; i++)
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d RF%x = 0x%x\n", path, i, odm_get_rf_reg(dm, (enum rf_path)path, i, 0xfffff));
	}
#endif
	return true;
}

boolean _dpk_one_shot_8814b(struct dm_struct *dm, u8 path, u8 action)
{
	u8 temp = 0x0;
	u16 dpk_cmd = 0x0;
	boolean result = false;

	temp = ((1 << (path + 4)) | (8 + (path << 1)));
	dpk_cmd = 0x1000 | (action << 8) | temp;
	odm_write_1byte(dm, 0x2d9c, 0x0);
	odm_write_1byte(dm, 0x1b10, 0x0);
	/*RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot dpk_cmd = 0x%x\n", dpk_cmd);*/
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd);
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd + 1);
	ODM_delay_us(50);
	
	result = _dpk_check_nctl_done_8814b(dm, path, dpk_cmd);	
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, IQK_CMD_8814B | (path << 1));
	return result;
}

void _dpk_bp_macbb_8814b(struct dm_struct *dm, u32 *mac_bp,
			 u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	for (i = 0; i < DPK_MAC_NUM_8814B; i++)
		mac_bp[i] = odm_read_4byte(dm, bp_mac_reg[i]);

	for (i = 0; i < DPK_BB_NUM_8814B; i++)
		bb_bp[i] = odm_read_4byte(dm, bp_bb_reg[i]);
}

void _dpk_bp_rf_8814b(struct dm_struct *dm, u32 rf_bp[][SS_8814B],
		      u32 *bp_reg)
{
	u8 i, s;

	for (s = 0; s < SS_8814B; s++) {
		for (i = 0; i < DPK_RF_NUM_8814B; i++) {
			rf_bp[i][s] = odm_get_rf_reg(dm, (enum rf_path)s,
						     bp_reg[i], MASK20BITS);
		}
	}
}


void _dpk_reload_macbb_8814b(struct dm_struct *dm, u32 *mac_bp,
			     u32 *bb_bp, u32 *bp_mac_reg, u32 *bp_bb_reg)
{
	u32 i;

	/*toggle IGI*/
	odm_write_4byte(dm, 0x1d70, 0x50505050);

	for (i = 0; i < DPK_MAC_NUM_8814B; i++)
		odm_write_4byte(dm, bp_mac_reg[i], mac_bp[i]);
	for (i = 0; i < DPK_BB_NUM_8814B; i++)
		odm_write_4byte(dm, bp_bb_reg[i], bb_bp[i]);

	/*rx go throughput IQK*/
	odm_set_bb_reg(dm, 0x180c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x410c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x520c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x530c, BIT(31), 0x1);

	//r_rftxen_gck_force_on
	odm_set_bb_reg(dm, 0x1834, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x4134, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5234, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5334, BIT(15), 0x1);
	
}
void _dpk_reload_rf_8814b(struct dm_struct *dm, u32 *reg,
			   u32 data[][SS_8814B])
{
	u32 i;

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, MASK20BITS, 0x0);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xdf, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0xdf, MASK20BITS, 0x0);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0xdf, MASK20BITS, 0x0);

	for (i = 0; i < DPK_RF_NUM_8814B; i++) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] reg[%d][0] = 0x%x\n", i, data[i][0]);
		odm_set_rf_reg(dm, RF_PATH_A, reg[i], 0xfffff, data[i][0]);
		odm_set_rf_reg(dm, RF_PATH_B, reg[i], 0xfffff, data[i][1]);
		odm_set_rf_reg(dm, RF_PATH_C, reg[i], 0xfffff, data[i][2]);
		odm_set_rf_reg(dm, RF_PATH_D, reg[i], 0xfffff, data[i][3]);
	}
}

void _dpk_mode_8814b(struct dm_struct *dm, boolean is_dpkmode)
{
	u32 temp1, temp2;
	/*RF & page 1b can't be write in iqk mode*/
	if (is_dpkmode)
		odm_set_bb_reg(dm, R_0x1cd0, BIT(31), 0x1);
	else
		odm_set_bb_reg(dm, R_0x1cd0, BIT(31), 0x0);
}

void _dpk_clear_lut_table_8814b(struct dm_struct *dm)
{
	u8 i;
	u32 reg_1bdc;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] clear lut table\n");

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |  RF_PATH_A << 1);	
	odm_write_1byte(dm, 0x1b54, 0x0);
	for (i = 0; i < 0x80; i++) {
		odm_set_bb_reg(dm, R_0x1b58, MASKDWORD, 0x00B88800 | i << 24);		
		odm_write_4byte(dm, 0x1b5c, 0x0);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}

	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |  RF_PATH_B << 1);	
	odm_write_1byte(dm, 0x1b54, 0x0);
	for (i = 0; i < 0x80; i++) {
		odm_set_bb_reg(dm, R_0x1b58, MASKDWORD, 0x00B88800 | i << 24);		
		odm_write_4byte(dm, 0x1b5c, 0x0);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}

	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |  RF_PATH_C << 1);	
	odm_write_1byte(dm, 0x1b54, 0x0);
	for (i = 0; i < 0x80; i++) {
		odm_set_bb_reg(dm, R_0x1b58, MASKDWORD, 0x00B88800 | i << 24);		
		odm_write_4byte(dm, 0x1b5c, 0x0);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}

	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |  RF_PATH_D << 1);	
	odm_write_1byte(dm, 0x1b54, 0x0);
	for (i = 0; i < 0x80; i++) {
		odm_set_bb_reg(dm, R_0x1b58, MASKDWORD, 0x00B88800 | i << 24);		
		odm_write_4byte(dm, 0x1b5c, 0x0);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}
	odm_write_4byte(dm, 0x1b58, 0x0);	
	odm_write_4byte(dm, 0x1b5c, 0x0);
}

void _dpk_rf_init_8814b(struct dm_struct *dm)
{
	static boolean firstrun = true;

	if (firstrun == true) {
		firstrun = false;
		odm_set_bb_reg(dm, R_0x1bb8, 0x00100000, 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x33, 0x0000f, 0x4);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3e, RFREGOFFSETMASK, 0x003f6);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3f, RFREGOFFSETMASK, 0x0f9f7);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x33, 0x0000f, 0x4);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x3e, RFREGOFFSETMASK, 0x003f6);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x3f, RFREGOFFSETMASK, 0x0f9f7);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x33, 0x0000f, 0x4);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x3e, RFREGOFFSETMASK, 0x003f6);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x3f, RFREGOFFSETMASK, 0x0f9f7);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x33, 0x0000f, 0x4);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x3e, RFREGOFFSETMASK, 0x003f6);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x3f, RFREGOFFSETMASK, 0x0f9f7);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x33, 0x0000f, 0x7);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3e, RFREGOFFSETMASK, 0x003fd);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3f, RFREGOFFSETMASK, 0xefcf7);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x33, 0x0000f, 0x7);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x3e, RFREGOFFSETMASK, 0x003fd);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x3f, RFREGOFFSETMASK, 0xefcf7);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x33, 0x0000f, 0x7);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x3e, RFREGOFFSETMASK, 0x003fd);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x3f, RFREGOFFSETMASK, 0xefcf7);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, RFREGOFFSETMASK, 0x00000);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x33, 0x0000f, 0x7);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x3e, RFREGOFFSETMASK, 0x003fd);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x3f, RFREGOFFSETMASK, 0xefcf7);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, RFREGOFFSETMASK, 0x00000);
	}
}

void _dpk_rfe_setting_8814b(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	//RF_DBG(dm, DBG_RF_DPK, "[DPK]rfe_type = %x\n", dm->rfe_type);
	switch (dm->rfe_type) {
	case 0x3 :		
	RF_DBG(dm, DBG_RF_DPK, "[DPK]rfe_type = %x\n", dm->rfe_type);
		odm_set_bb_reg(dm, 0x183c, BIT(4), 0x1);
		odm_set_bb_reg(dm, 0x413c, BIT(13), 0x1);
		odm_set_bb_reg(dm, 0x523c, BIT(8), 0x1);		
		odm_set_bb_reg(dm, 0x533c, BIT(10), 0x1);
		odm_set_bb_reg(dm, 0x1840, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x1844, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x4140, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x4144, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x5240, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x5244, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x5340, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, 0x5344, MASKDWORD, 0x77777777);
		break;
	default:
		break;
	}
	
}

void _dpk_init_8814b(struct dm_struct *dm, boolean start_dpk)
{
	int path;
	
	RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK INIT setting!!!\n");
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B |  RF_PATH_A << 1);	
	if (start_dpk) {
#if 0
		odm_write_4byte(dm, 0x1b08, 0x00000080);
		odm_write_4byte(dm, 0x1b00, 0x00A70008);
		odm_write_4byte(dm, 0x1b00, 0x00150008);
		odm_write_4byte(dm, 0x1b00, 0x00000008);
		odm_write_4byte(dm, 0x1b04, 0xE24628D2);
		odm_write_4byte(dm, 0x1b04, 0xE24628D6);
		odm_write_4byte(dm, 0x1b0c, 0x00000000);
		odm_write_4byte(dm, 0x1b10, 0x00010C00);
		odm_write_4byte(dm, 0x1b14, 0x00000000);
		odm_write_4byte(dm, 0x1b18, 0x00292903);
		odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
		odm_write_4byte(dm, 0x1b20, 0x01040008);
		odm_write_4byte(dm, 0x1b24, 0x00060008);
		odm_write_4byte(dm, 0x1b28, 0x80060300);
		odm_write_4byte(dm, 0x1b2C, 0x00180018);
		odm_write_4byte(dm, 0x1b30, 0x40000000);
		odm_write_4byte(dm, 0x1b34, 0x00000800);
		odm_write_4byte(dm, 0x1b38, 0x40000000);
		odm_write_4byte(dm, 0x1b3C, 0x40000000);
		odm_write_4byte(dm, 0x1bc0, 0x01000000);
		odm_write_4byte(dm, 0x1bcc, 0x00000000);
		odm_write_4byte(dm, 0x1be4, 0x00000000);
		odm_write_4byte(dm, 0x1bec, 0x40000000);
#endif
		odm_write_4byte(dm, 0x1b40, 0x40000000);
		odm_write_4byte(dm, 0x1b44, 0x24002064);
		odm_write_4byte(dm, 0x1b48, 0x0005002D);
		odm_write_4byte(dm, 0x1b54, 0x00100002);
		odm_write_4byte(dm, 0x1b60, 0x1F0f0000);
		odm_write_4byte(dm, 0x1b64, 0x1C100000);
		odm_write_4byte(dm, 0x1b40, 0x00000000);
		odm_write_4byte(dm, 0x1b4c, 0x00000000);
		odm_write_4byte(dm, 0x1b4c, 0x008a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000377);
		odm_write_4byte(dm, 0x1b4c, 0x018a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000054B);
		odm_write_4byte(dm, 0x1b4c, 0x028a0000);
		odm_write_4byte(dm, 0x1b50, 0x000006A2);
		odm_write_4byte(dm, 0x1b4c, 0x038a0000);
		odm_write_4byte(dm, 0x1b50, 0x000007BF);
		odm_write_4byte(dm, 0x1b4c, 0x048a0000);
		odm_write_4byte(dm, 0x1b50, 0x000008B8);
		odm_write_4byte(dm, 0x1b4c, 0x058a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000997);
		odm_write_4byte(dm, 0x1b4c, 0x068a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000A64);
		odm_write_4byte(dm, 0x1b4c, 0x078a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000B23);
		odm_write_4byte(dm, 0x1b4c, 0x088a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000BD5);
		odm_write_4byte(dm, 0x1b4c, 0x098a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000C7D);
		odm_write_4byte(dm, 0x1b4c, 0x0a8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000D1D);
		odm_write_4byte(dm, 0x1b4c, 0x0b8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000DB6);
		odm_write_4byte(dm, 0x1b4c, 0x0c8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000E48);
		odm_write_4byte(dm, 0x1b4c, 0x0d8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000ED5);
		odm_write_4byte(dm, 0x1b4c, 0x0e8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000F5D);
		odm_write_4byte(dm, 0x1b4c, 0x0f8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00000FE0);
		odm_write_4byte(dm, 0x1b4c, 0x108a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000105F);
		odm_write_4byte(dm, 0x1b4c, 0x118a0000);
		odm_write_4byte(dm, 0x1b50, 0x000010DA);
		odm_write_4byte(dm, 0x1b4c, 0x128a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001152);
		odm_write_4byte(dm, 0x1b4c, 0x138a0000);
		odm_write_4byte(dm, 0x1b50, 0x000011C7);
		odm_write_4byte(dm, 0x1b4c, 0x148a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001239);
		odm_write_4byte(dm, 0x1b4c, 0x158a0000);
		odm_write_4byte(dm, 0x1b50, 0x000012A8);
		odm_write_4byte(dm, 0x1b4c, 0x168a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001314);
		odm_write_4byte(dm, 0x1b4c, 0x178a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000137E);
		odm_write_4byte(dm, 0x1b4c, 0x188a0000);
		odm_write_4byte(dm, 0x1b50, 0x000013E6);
		odm_write_4byte(dm, 0x1b4c, 0x198a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000144C);
		odm_write_4byte(dm, 0x1b4c, 0x1a8a0000);
		odm_write_4byte(dm, 0x1b50, 0x000014B0);
		odm_write_4byte(dm, 0x1b4c, 0x1b8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001512);
		odm_write_4byte(dm, 0x1b4c, 0x1c8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001573);
		odm_write_4byte(dm, 0x1b4c, 0x1d8a0000);
		odm_write_4byte(dm, 0x1b50, 0x000015D1);
		odm_write_4byte(dm, 0x1b4c, 0x1e8a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000162E);
		odm_write_4byte(dm, 0x1b4c, 0x1f8a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000168A);
		odm_write_4byte(dm, 0x1b4c, 0x208a0000);
		odm_write_4byte(dm, 0x1b50, 0x000016E4);
		odm_write_4byte(dm, 0x1b4c, 0x218a0000);
		odm_write_4byte(dm, 0x1b50, 0x0000173D);
		odm_write_4byte(dm, 0x1b4c, 0x228a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001794);
		odm_write_4byte(dm, 0x1b4c, 0x238a0000);
		odm_write_4byte(dm, 0x1b50, 0x000017EB);
		odm_write_4byte(dm, 0x1b4c, 0x248a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001840);
		odm_write_4byte(dm, 0x1b4c, 0x258a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001894);
		odm_write_4byte(dm, 0x1b4c, 0x268a0000);
		odm_write_4byte(dm, 0x1b50, 0x000018E6);
		odm_write_4byte(dm, 0x1b4c, 0x278a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001938);
		odm_write_4byte(dm, 0x1b4c, 0x288a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001989);
		odm_write_4byte(dm, 0x1b4c, 0x298a0000);
		odm_write_4byte(dm, 0x1b50, 0x000019D8);
		odm_write_4byte(dm, 0x1b4c, 0x2a8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001A27);
		odm_write_4byte(dm, 0x1b4c, 0x2b8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001A75);
		odm_write_4byte(dm, 0x1b4c, 0x2c8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001AC2);
		odm_write_4byte(dm, 0x1b4c, 0x2d8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001B0E);
		odm_write_4byte(dm, 0x1b4c, 0x2e8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001B59);
		odm_write_4byte(dm, 0x1b4c, 0x2f8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001BA4);
		odm_write_4byte(dm, 0x1b4c, 0x308a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001BEE);
		odm_write_4byte(dm, 0x1b4c, 0x318a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001C37);
		odm_write_4byte(dm, 0x1b4c, 0x328a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001C7F);
		odm_write_4byte(dm, 0x1b4c, 0x338a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001CC6);
		odm_write_4byte(dm, 0x1b4c, 0x348a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001D0D);
		odm_write_4byte(dm, 0x1b4c, 0x358a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001D53);
		odm_write_4byte(dm, 0x1b4c, 0x368a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001D99);
		odm_write_4byte(dm, 0x1b4c, 0x378a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001DDE);
		odm_write_4byte(dm, 0x1b4c, 0x388a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001E22);
		odm_write_4byte(dm, 0x1b4c, 0x398a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001E66);
		odm_write_4byte(dm, 0x1b4c, 0x3a8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001EA9);
		odm_write_4byte(dm, 0x1b4c, 0x3b8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001EEB);
		odm_write_4byte(dm, 0x1b4c, 0x3c8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001F2D);
		odm_write_4byte(dm, 0x1b4c, 0x3d8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001F6F);
		odm_write_4byte(dm, 0x1b4c, 0x3e8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001FB0);
		odm_write_4byte(dm, 0x1b4c, 0x3f8a0000);
		odm_write_4byte(dm, 0x1b50, 0x00001FF0);
		odm_write_4byte(dm, 0x1b4c, 0x00000000);
		odm_write_4byte(dm, 0x1b50, 0x00000000);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b58, 0x00898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0CA60FED);
		odm_write_4byte(dm, 0x1b58, 0x02898F00);
		odm_write_4byte(dm, 0x1b5C, 0x07FB0A0C);
		odm_write_4byte(dm, 0x1b58, 0x04898F00);
		odm_write_4byte(dm, 0x1b5C, 0x05090657);
		odm_write_4byte(dm, 0x1b58, 0x06898F00);
		odm_write_4byte(dm, 0x1b5C, 0x032D0400);
		odm_write_4byte(dm, 0x1b58, 0x08898F00);
		odm_write_4byte(dm, 0x1b5C, 0x02010286);
		odm_write_4byte(dm, 0x1b58, 0x0A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x01440198);
		odm_write_4byte(dm, 0x1b58, 0x0C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00CC0101);
		odm_write_4byte(dm, 0x1b58, 0x0E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x008100A2);
		odm_write_4byte(dm, 0x1b58, 0x10898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00510066);
		odm_write_4byte(dm, 0x1b58, 0x12898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00330041);
		odm_write_4byte(dm, 0x1b58, 0x14898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00200029);
		odm_write_4byte(dm, 0x1b58, 0x16898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0014001A);
		odm_write_4byte(dm, 0x1b58, 0x18898F00);
		odm_write_4byte(dm, 0x1b5C, 0x000D0010);
		odm_write_4byte(dm, 0x1b58, 0x1A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0008000A);
		odm_write_4byte(dm, 0x1b58, 0x1C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00050006);
		odm_write_4byte(dm, 0x1b58, 0x1E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00030004);
		odm_write_4byte(dm, 0x1b58, 0x20898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00020003);
		odm_write_4byte(dm, 0x1b58, 0x22898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00010002);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b5C, 0x00000000);
		odm_write_4byte(dm, 0x1b00, 0x0000000A);
#if 0
		odm_write_4byte(dm, 0x1b00, 0x0000000A);
		odm_write_4byte(dm, 0x1b00, 0x00A7000A);
		odm_write_4byte(dm, 0x1b00, 0x0015000A);
		odm_write_4byte(dm, 0x1b00, 0x0000000A);
		odm_write_4byte(dm, 0x1b04, 0xE24628D6);
		odm_write_4byte(dm, 0x1b0c, 0x00000000);
		odm_write_4byte(dm, 0x1b10, 0x00010C00);
		odm_write_4byte(dm, 0x1b14, 0x00000000);
		odm_write_4byte(dm, 0x1b18, 0x00292903);
		odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
		odm_write_4byte(dm, 0x1b20, 0x01040008);
		odm_write_4byte(dm, 0x1b24, 0x00060008);
		odm_write_4byte(dm, 0x1b28, 0x00060300);
		odm_write_4byte(dm, 0x1b2C, 0x00180018);
		odm_write_4byte(dm, 0x1b30, 0x40000000);
		odm_write_4byte(dm, 0x1b34, 0x00000800);
		odm_write_4byte(dm, 0x1b38, 0x40000000);
		odm_write_4byte(dm, 0x1b3C, 0x40000000);
		odm_write_4byte(dm, 0x1bc0, 0x01000000);
		odm_write_4byte(dm, 0x1bcc, 0x00000000);
		odm_write_4byte(dm, 0x1be4, 0x00000000);
		odm_write_4byte(dm, 0x1bec, 0x40000000);
#endif
		odm_write_4byte(dm, 0x1b54, 0x00100002);
		odm_write_4byte(dm, 0x1b60, 0x1F0f0000);
		odm_write_4byte(dm, 0x1b64, 0x1C100000);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b58, 0x00898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0CA60FED);
		odm_write_4byte(dm, 0x1b58, 0x02898F00);
		odm_write_4byte(dm, 0x1b5C, 0x07FB0A0C);
		odm_write_4byte(dm, 0x1b58, 0x04898F00);
		odm_write_4byte(dm, 0x1b5C, 0x05090657);
		odm_write_4byte(dm, 0x1b58, 0x06898F00);
		odm_write_4byte(dm, 0x1b5C, 0x032D0400);
		odm_write_4byte(dm, 0x1b58, 0x08898F00);
		odm_write_4byte(dm, 0x1b5C, 0x02010286);
		odm_write_4byte(dm, 0x1b58, 0x0A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x01440198);
		odm_write_4byte(dm, 0x1b58, 0x0C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00CC0101);
		odm_write_4byte(dm, 0x1b58, 0x0E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x008100A2);
		odm_write_4byte(dm, 0x1b58, 0x10898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00510066);
		odm_write_4byte(dm, 0x1b58, 0x12898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00330041);
		odm_write_4byte(dm, 0x1b58, 0x14898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00200029);
		odm_write_4byte(dm, 0x1b58, 0x16898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0014001A);
		odm_write_4byte(dm, 0x1b58, 0x18898F00);
		odm_write_4byte(dm, 0x1b5C, 0x000D0010);
		odm_write_4byte(dm, 0x1b58, 0x1A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0008000A);
		odm_write_4byte(dm, 0x1b58, 0x1C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00050006);
		odm_write_4byte(dm, 0x1b58, 0x1E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00030004);
		odm_write_4byte(dm, 0x1b58, 0x20898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00020003);
		odm_write_4byte(dm, 0x1b58, 0x22898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00010002);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b5C, 0x00000000);
		odm_write_4byte(dm, 0x1b00, 0x0000000C);
#if 0
		odm_write_4byte(dm, 0x1b00, 0x00A7000C);
		odm_write_4byte(dm, 0x1b00, 0x0015000C);
		odm_write_4byte(dm, 0x1b00, 0x0000000C);
		odm_write_4byte(dm, 0x1b04, 0xE24628D6);
		odm_write_4byte(dm, 0x1b0c, 0x00000000);
		odm_write_4byte(dm, 0x1b10, 0x00010C00);
		odm_write_4byte(dm, 0x1b14, 0x00000000);
		odm_write_4byte(dm, 0x1b18, 0x00292903);
		odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
		odm_write_4byte(dm, 0x1b20, 0x01040008);
		odm_write_4byte(dm, 0x1b24, 0x00060008);
		odm_write_4byte(dm, 0x1b28, 0x80060300);
		odm_write_4byte(dm, 0x1b2C, 0x00180018);
		odm_write_4byte(dm, 0x1b30, 0x40000000);
		odm_write_4byte(dm, 0x1b34, 0x00000800);
		odm_write_4byte(dm, 0x1b38, 0x40000000);
		odm_write_4byte(dm, 0x1b3C, 0x40000000);
		odm_write_4byte(dm, 0x1bc0, 0x01000000);
		odm_write_4byte(dm, 0x1bcc, 0x00000000);
		odm_write_4byte(dm, 0x1be4, 0x00000000);
		odm_write_4byte(dm, 0x1bec, 0x40000000);
#endif
		odm_write_4byte(dm, 0x1b54, 0x00100002);
		odm_write_4byte(dm, 0x1b60, 0x1F0f0000);
		odm_write_4byte(dm, 0x1b64, 0x1C100000);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b58, 0x00898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0CA60FED);
		odm_write_4byte(dm, 0x1b58, 0x02898F00);
		odm_write_4byte(dm, 0x1b5C, 0x07FB0A0C);
		odm_write_4byte(dm, 0x1b58, 0x04898F00);
		odm_write_4byte(dm, 0x1b5C, 0x05090657);
		odm_write_4byte(dm, 0x1b58, 0x06898F00);
		odm_write_4byte(dm, 0x1b5C, 0x032D0400);
		odm_write_4byte(dm, 0x1b58, 0x08898F00);
		odm_write_4byte(dm, 0x1b5C, 0x02010286);
		odm_write_4byte(dm, 0x1b58, 0x0A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x01440198);
		odm_write_4byte(dm, 0x1b58, 0x0C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00CC0101);
		odm_write_4byte(dm, 0x1b58, 0x0E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x008100A2);
		odm_write_4byte(dm, 0x1b58, 0x10898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00510066);
		odm_write_4byte(dm, 0x1b58, 0x12898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00330041);
		odm_write_4byte(dm, 0x1b58, 0x14898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00200029);
		odm_write_4byte(dm, 0x1b58, 0x16898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0014001A);
		odm_write_4byte(dm, 0x1b58, 0x18898F00);
		odm_write_4byte(dm, 0x1b5C, 0x000D0010);
		odm_write_4byte(dm, 0x1b58, 0x1A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0008000A);
		odm_write_4byte(dm, 0x1b58, 0x1C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00050006);
		odm_write_4byte(dm, 0x1b58, 0x1E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00030004);
		odm_write_4byte(dm, 0x1b58, 0x20898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00020003);
		odm_write_4byte(dm, 0x1b58, 0x22898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00010002);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b5C, 0x00000000);
		odm_write_4byte(dm, 0x1b00, 0x0000000E);
#if 0
		odm_write_4byte(dm, 0x1b00, 0x00A7000E);
		odm_write_4byte(dm, 0x1b00, 0x0015000E);
		odm_write_4byte(dm, 0x1b00, 0x0000000E);
		odm_write_4byte(dm, 0x1b04, 0xE24628D6);
		odm_write_4byte(dm, 0x1b0c, 0x00000000);
		odm_write_4byte(dm, 0x1b10, 0x00010C00);
		odm_write_4byte(dm, 0x1b14, 0x00000000);
		odm_write_4byte(dm, 0x1b18, 0x00292903);
		odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
		odm_write_4byte(dm, 0x1b20, 0x01040008);
		odm_write_4byte(dm, 0x1b24, 0x00060008);
		odm_write_4byte(dm, 0x1b28, 0x80060300);
		odm_write_4byte(dm, 0x1b2C, 0x00180018);
		odm_write_4byte(dm, 0x1b30, 0x40000000);
		odm_write_4byte(dm, 0x1b34, 0x00000800);
		odm_write_4byte(dm, 0x1b38, 0x40000000);
		odm_write_4byte(dm, 0x1b3C, 0x40000000);
		odm_write_4byte(dm, 0x1bc0, 0x01000000);
		odm_write_4byte(dm, 0x1bcc, 0x00000000);
		odm_write_4byte(dm, 0x1be4, 0x00000000);
		odm_write_4byte(dm, 0x1bec, 0x40000000);
#endif
		odm_write_4byte(dm, 0x1b54, 0x00100002);
		odm_write_4byte(dm, 0x1b60, 0x1F0f0000);
		odm_write_4byte(dm, 0x1b64, 0x1C100000);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b58, 0x00898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0CA60FED);
		odm_write_4byte(dm, 0x1b58, 0x02898F00);
		odm_write_4byte(dm, 0x1b5C, 0x07FB0A0C);
		odm_write_4byte(dm, 0x1b58, 0x04898F00);
		odm_write_4byte(dm, 0x1b5C, 0x05090657);
		odm_write_4byte(dm, 0x1b58, 0x06898F00);
		odm_write_4byte(dm, 0x1b5C, 0x032D0400);
		odm_write_4byte(dm, 0x1b58, 0x08898F00);
		odm_write_4byte(dm, 0x1b5C, 0x02010286);
		odm_write_4byte(dm, 0x1b58, 0x0A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x01440198);
		odm_write_4byte(dm, 0x1b58, 0x0C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00CC0101);
		odm_write_4byte(dm, 0x1b58, 0x0E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x008100A2);
		odm_write_4byte(dm, 0x1b58, 0x10898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00510066);
		odm_write_4byte(dm, 0x1b58, 0x12898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00330041);
		odm_write_4byte(dm, 0x1b58, 0x14898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00200029);
		odm_write_4byte(dm, 0x1b58, 0x16898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0014001A);
		odm_write_4byte(dm, 0x1b58, 0x18898F00);
		odm_write_4byte(dm, 0x1b5C, 0x000D0010);
		odm_write_4byte(dm, 0x1b58, 0x1A898F00);
		odm_write_4byte(dm, 0x1b5C, 0x0008000A);
		odm_write_4byte(dm, 0x1b58, 0x1C898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00050006);
		odm_write_4byte(dm, 0x1b58, 0x1E898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00030004);
		odm_write_4byte(dm, 0x1b58, 0x20898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00020003);
		odm_write_4byte(dm, 0x1b58, 0x22898F00);
		odm_write_4byte(dm, 0x1b5C, 0x00010002);
		odm_write_4byte(dm, 0x1b58, 0x00000000);
		odm_write_4byte(dm, 0x1b5C, 0x00000000);
	}
	return;
}

void _dpk_nctl_8814b(struct dm_struct *dm)
{
	return;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK NCTL setting!!!\n");
}

void _dpk_pas_gl_read_8814b(struct dm_struct *dm, u8 path)
{
	u8 k, j;
	u32 reg_1bfc, reg_1b4c, tmp;

	RF_DBG(dm, DBG_RF_DPK, "\n");
	RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_PAS_GL_read_8814b\n");	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | 0x8);
	odm_write_1byte(dm, 0x1b49, 0x00);
	odm_write_4byte(dm, 0x1bd4, 0x00060001);		

	RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b00 = 0x%x, 0x1bd4 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0x1b00, MASKDWORD),
	       odm_get_bb_reg(dm, R_0x1bd4, MASKDWORD));
	for (k = 0; k < 8; k++) {
		//1st
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x00080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
		}
	
	for (k = 0; k < 8; k++) {
		//2nd		
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x08080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//3rd
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x10080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//4th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x18080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//5th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x20080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//6th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x28080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//7th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x30080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
	//8th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x38080000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	RF_DBG(dm, DBG_RF_DPK, "\n");	
	odm_write_4byte(dm, 0x1b4c, 0x00000000);
}

void _dpk_pas_dpk_read_8814b(struct dm_struct *dm, u8 path)
{
	u8 k, j;
	u32 reg_1bfc, tmp;

	RF_DBG(dm, DBG_RF_DPK, "\n");
	RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_pas_dpk_read_8814b\n");	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | 0x8);
	odm_write_1byte(dm, 0x1b49, 0x00);		
	odm_write_4byte(dm, 0x1bd4, 0x00060001);		
	//odm_write_4byte(dm, 0x1b4c, 0x00000000);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bd4 = 0x%x, 0x1b4c = 0x%x\n",
	       odm_get_bb_reg(dm, R_0x1bd4, MASKDWORD),
	       odm_get_bb_reg(dm, R_0x1b4c, MASKDWORD));
	for (k = 0; k < 8; k++) {
		//1st
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x00090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//2nd
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x08090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//3rd
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x10090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//4th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x18090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//5th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x20090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}	
	for (k = 0; k < 8; k++) {
		//6th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x28090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//7th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x30090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	
	for (k = 0; k < 8; k++) {
		//8th
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, (0x38090000 | k << 24));
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	RF_DBG(dm, DBG_RF_DPK, "\n");	
	odm_write_4byte(dm, 0x1b4c, 0x00000000);
}

u32 _dpk_pas_get_iq_8814b(
	struct dm_struct *dm,
	u8 gs_type)
{
	s32 i_val = 0, q_val = 0;

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | 0x8);
	odm_write_1byte(dm, 0x1b49, 0x00);

	if (gs_type == GSK3) {
		odm_write_4byte(dm, 0x1bd4, 0x00060001);
		odm_write_4byte(dm, 0x1b4c, 0x00080000);
	} else if (gs_type == GSK2){
		odm_write_4byte(dm, 0x1bd4, 0x00060001);
		odm_write_4byte(dm, 0x1b4c, 0x37080000);
	} else if(gs_type == GSK1) {
		odm_write_4byte(dm, 0x1bd4, 0x00060001);
		odm_write_4byte(dm, 0x1b4c, 0x3F080000);
	}

	i_val = odm_get_bb_reg(dm, R_0x1bfc, MASKHWORD);
	q_val = odm_get_bb_reg(dm, R_0x1bfc, MASKLWORD);

	if (i_val >> 15 != 0)
		i_val = 0x10000 - i_val;
	if (q_val >> 15 != 0)
		q_val = 0x10000 - q_val;
	
	odm_write_4byte(dm, 0x1b4c, 0x0);
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%x] i=0x%x, q=0x%x, i^2+q^2=0x%x\n",
	       gs_type, i_val, q_val, i_val*i_val + q_val*q_val);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%x] i=%d, q=%d, i^2+q^2=%d\n",
	       gs_type, i_val, q_val, i_val*i_val + q_val*q_val);

#endif
	return i_val*i_val + q_val*q_val;
}



s32 _dpk_pas_iq_check_8814b(
	struct dm_struct *dm,
	u8 path,
	u8 gs_type)
{
	u8 result = 0;
	u32 i_val = 0, q_val = 0, loss = 0, gain = 0;
	s32 loss_db = 0;
	s32 gain_db = 0;
	s32 gain_db2 = 0;

	gain = _dpk_pas_get_iq_8814b(dm, gs_type) >> 3; //offset 90db
	gain_db =  (s32)(3 *(halrf_psd_log2base(gain)/10 - 280));
	gain_db2 = halrf_psd_log2base(gain);

#if 1
	//RF_DBG(dm, DBG_RF_DPK, "[DPK][G%d] i^2+q^2= %d\n", gs_type, gain);
	//RF_DBG(dm, DBG_RF_DPK, "[DPK][G%d] log(gain)= %d\n", gs_type, gain_db2);	
	RF_DBG(dm, DBG_RF_DPK, "[DPK][G%d] Gain_db= %d\n", gs_type, gain_db);
#endif
	return gain_db;

}

boolean _dpk_pas_rxbbagc_8814b(
	struct dm_struct *dm,
	u8 path,
	u8 gs_type)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 tmp_txagc, tmp_rxbb, i = 0;
	s32 gain_db;
	u32 rf0;
	boolean fail = true, isbnd = false;
/*	
	if (gs_type == GSK1) {
		gain_db = _dpk_pas_iq_check_8814b(dm, path, gsinsearchK);	
	} else {
		gain_db = _dpk_pas_iq_check_8814b(dm, path, gsinsearchK);
		gain_db = gain_db - (dpk_info->tx_gain * 10);		
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][AGC] dpk_info->tx_gain= 0x%x, gain_db= 0x%x\n",
		       dpk_info->tx_gain, gain_db);		
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][AGC] dpk_info->tx_gain= %d, gain_db= %d\n",
		       dpk_info->tx_gain, gain_db);
	}
*/
	if (gs_type == GSK3) {
		gain_db = _dpk_pas_iq_check_8814b(dm, path, gs_type);		
		tmp_rxbb = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
			    RF_0x00, 0x003e0);
		rf0 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0xfffff);
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] old rf0 = 0x%x\n", rf0);
		if (gain_db > -110) { //> -2dB
			tmp_rxbb = tmp_rxbb - 1;			
			fail = true;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] Case 4\n");
#if 0
		} else if (gain_db < -165){ // <-6.5dB
			tmp_rxbb = tmp_rxbb + 1;
			fail = true;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] Case 5\n");
#endif
		} else {
			fail = false;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] Case 6\n");
		}
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x003e0, tmp_rxbb);
		rf0 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0xfffff);
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] new rf0 = 0x%x\n", rf0);
	}
	
	if (gs_type == GSK2)
		fail = false;

	if (gs_type == GSK1) {
		gain_db = _dpk_pas_iq_check_8814b(dm, path, gs_type);

		tmp_txagc = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
			    RF_0x00, 0x0001f);
		tmp_rxbb = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
			    RF_0x00, 0x003e0);

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][GSK1] old TXAGC=0x%x, RXBB=0x%x\n",
		       tmp_txagc, tmp_rxbb);
		if (gain_db < -185){ //-9.5dB
			if (tmp_rxbb >= 0x1d) {
				isbnd = true;
				tmp_rxbb = 0x1f;
				tmp_txagc = tmp_txagc  + 2;
			} else			
				tmp_rxbb = tmp_rxbb + 2;//3    
			fail = true;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 1\n");
		} else if (gain_db > -115){ // -2.5dB
			if(tmp_rxbb  <= 0x3) {				
				isbnd = true;
				tmp_rxbb = 0x1;
				tmp_txagc = tmp_txagc - 2;
			} else
				tmp_rxbb = tmp_rxbb - 2;
			fail = true;			
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 2\n");
		} else {
			fail = false;			
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 3\n");
		}
		if (isbnd == true)
			fail = true;

		if (fail) {
			odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
			odm_set_rf_reg(dm, (enum rf_path)path,
				    RF_0x00, 0x003e0, tmp_rxbb);
			odm_set_rf_reg(dm, (enum rf_path)path,
				    RF_0x00, 0x0001f, tmp_txagc);
		} else {
			dpk_info->txbb[path] = tmp_txagc;
			dpk_info->rxbb[path] = tmp_rxbb;
		}

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK][GSK1] new TXAGC=0x%x, RXBB=0x%x\n",
		       tmp_txagc, tmp_rxbb);		
		rf0 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0xfffff);
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] rf0=0x%x\n", rf0);
	}
	return fail;

}
boolean _dpk_pas_agc_8814b(
	struct dm_struct *dm,
	u8 path,
	u8 gs)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u32 rf0;
	boolean fail = true, kfail = true;

	RF_DBG(dm, DBG_RF_DPK, "[DPK]===GS %d DPK GainSearch ===\n", path);
//step 1
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_1byte(dm, 0x1b49, 0x0);
	
	rf0 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0xfffff);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] rf0 = 0x%x\n", rf0);
	
	kfail = _dpk_one_shot_8814b(dm, path, 0x0);

#if 0
	if (DPK_PAS_DBG_8814B)
		_dpk_pas_gl_read_8814b(dm, path); 
#endif
	fail = _dpk_pas_rxbbagc_8814b(dm, path, gs);

	return fail;
}

void _dpk_tx_pause_8814b(
	struct dm_struct *dm)
{
	u8 reg_rf0_a, reg_rf0_b, reg_rf0_c, reg_rf0_d;
	u16 count = 0;

	odm_write_1byte(dm, R_0x522, 0xff);
	odm_set_bb_reg(dm, R_0x1e70, 0x0000000f, 0x2);

	reg_rf0_a = (u8)odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0xF0000);
	reg_rf0_b = (u8)odm_get_rf_reg(dm, RF_PATH_B, RF_0x00, 0xF0000);
	reg_rf0_c = (u8)odm_get_rf_reg(dm, RF_PATH_C, RF_0x00, 0xF0000);
	reg_rf0_d = (u8)odm_get_rf_reg(dm, RF_PATH_D, RF_0x00, 0xF0000);
	
	while (((reg_rf0_a == 2) || (reg_rf0_b == 2) ||
	       (reg_rf0_d == 2) || (reg_rf0_c == 2)) && count < 2500) {
		reg_rf0_a = (u8)odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0xF0000);
		reg_rf0_b = (u8)odm_get_rf_reg(dm, RF_PATH_B, RF_0x00, 0xF0000);
		reg_rf0_c = (u8)odm_get_rf_reg(dm, RF_PATH_C, RF_0x00, 0xF0000);
		reg_rf0_d = (u8)odm_get_rf_reg(dm, RF_PATH_D, RF_0x00, 0xF0000);
		ODM_delay_us(2);
		count++;
	}
	RF_DBG(dm, DBG_RF_DPK, "[DPK] Tx pause!!\n");
}


void _dpk_mac_bb_setting_8814b(struct dm_struct *dm)
{
	/*MACBB register setting*/
	//_dpk_tx_pause_8814b(dm);
	odm_write_1byte(dm, REG_TXPAUSE, 0xff);
	//odm_set_bb_reg(dm, R_0x550, BIT(11) | BIT(3), 0x0);
	/*tx go throughput IQK*/
	odm_set_bb_reg(dm, 0x1e24, BIT(17), 0x1);
	/*enable IQK block*/
	odm_set_bb_reg(dm, 0x1cd0, 0xf0000000, 0x7);
	/*Turn off CCA*/
	/*odm_set_bb_reg(dm, 0x1c68, 0x0f000000, 0xf);*/
	/*Release gated clk*/
	odm_set_bb_reg(dm, 0x1834, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x4134, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5234, BIT(15), 0x1);
	odm_set_bb_reg(dm, 0x5334, BIT(15), 0x1);
	/*dont_rst_sync_path_when_txon*/
	odm_set_bb_reg(dm, 0x1d60, BIT(31), 0x1);
	//Prevent anapar state unknown at sine PSD
	/*OFDM/CCK off*/
	/*odm_set_bb_reg(dm, 0x1c3c, BIT(0), 0x0);*/
	/*odm_set_bb_reg(dm, 0x1c3c, BIT(1), 0x0);*/
	odm_set_bb_reg(dm, 0x1a14, 0x300, 0x3);
	/*prevent CCK CCA*/
	odm_set_bb_reg(dm, 0x1a00, 0x3, 0x2);
	/*rx path on*/
	odm_set_bb_reg(dm, 0x824, 0xf0000, 0xf);
	/*tx_scale_0dB*/
	odm_set_bb_reg(dm, 0x186c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x416c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x526c, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0x536c, BIT(7), 0x0);
	/*3-wire off*/
	odm_set_bb_reg(dm, 0x180c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x410c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x520c, 0x3, 0x0);
	odm_set_bb_reg(dm, 0x530c, 0x3, 0x0);
	/*CIP power on*/	
	odm_set_bb_reg(dm, R_0x1b08, BIT(7), 0x1);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] MAC/BB setting for DPK mode\n");
}

void _dpk_manual_txagc_8814b(struct dm_struct *dm, boolean is_manual)
{
	odm_set_bb_reg(dm, R_0x18a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x41a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x52a4, BIT(7), is_manual);
	odm_set_bb_reg(dm, R_0x53a4, BIT(7), is_manual);

}

void _dpk_rfsetting_8814b(struct dm_struct *dm, u8 path)
{
	struct dm_iqk_info	*iqk_info = &dm->IQK_info;
	u32 rf_reg00 = 0x0l, rf0;
	u8 tx_agc_init_value = 0x1c; /* DPK TXAGC value*/
	u8 rxbb = 0x0, mixgain = 0x0;
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	//ODM_delay_ms(1);

	if (*dm->band_type == ODM_BAND_2_4G) {
		tx_agc_init_value = 0x1a;
		//tx_agc_init_value = 0x18;
		rf_reg00 = 0x50000 + tx_agc_init_value; /* set TXAGC value*/
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0xfffff, rf_reg00);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x5c, 0x3000, 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x5c, 0xf0000, 0xe);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x80, BIT(10), 0x1);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0x3e0, 0x5);
		odm_set_rf_reg(dm, (enum rf_path)path, 0xdf, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x88, 0x300, 0x2);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x88, 0xc00, 0x0);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8e, BIT(5), 0x0);
	} else {
		if (path == 0x0) {
			tx_agc_init_value = 0x1c;
			rxbb = 0x7;
			mixgain = 0xb;
		} else if (path == 0x1) {
			tx_agc_init_value = 0x1c;
			rxbb = 0x7;
			mixgain = 0xb;
		} else if (path == 0x2) {
			tx_agc_init_value = 0x1c;
			rxbb = 0x7;
			mixgain = 0xb;
		} else if (path == 0x3) {
			tx_agc_init_value = 0x1c;
			rxbb = 0x7;
			mixgain = 0xb;
		}
		
		rf_reg00 = 0x50000 + tx_agc_init_value; /* set TXAGC value*/
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0xfffff, rf_reg00);
 		odm_set_rf_reg(dm, (enum rf_path)path, 0x63, 0x30000, 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x63, 0xf000, 0xe);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8c, BIT(4), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8c, 0x1e0, mixgain);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0x3e0, rxbb);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x8e, BIT(5), 0x0);
 	}
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][RF] RF_0x00 = %x\n",odm_get_rf_reg(dm, path, 0x00, 0xfffff));	
	RF_DBG(dm, DBG_RF_DPK, "[DPK][RF] RF_0x63 = %x\n",odm_get_rf_reg(dm, path, 0x63, 0xfffff));	
	RF_DBG(dm, DBG_RF_DPK, "[DPK][RF] RF_0x8c = %x\n",odm_get_rf_reg(dm, path, 0x8c, 0xfffff));	
#endif
}

void _dpk_afe_pre_setting_8814b(struct dm_struct *dm, boolean is_do_dpk)
{
	
	if (is_do_dpk) {
		odm_write_4byte(dm, 0x1810, 0x0005c304);
		odm_write_4byte(dm, 0x1814, 0x506aa234);
		odm_write_4byte(dm, 0x1818, 0x000004ff);
#if 0
		odm_write_4byte(dm, 0x18b0, 0x0809fb09);
		odm_write_4byte(dm, 0x18b4, 0x00000000);
		odm_write_4byte(dm, 0x18bc, 0x00c3ff80);
		odm_write_4byte(dm, 0x18c0, 0x0002c100);
		odm_write_4byte(dm, 0x18c4, 0x00000004);
		odm_write_4byte(dm, 0x18c8, 0x001fffe0);
#endif
		odm_write_4byte(dm, 0x4110, 0x0005c304);
		odm_write_4byte(dm, 0x4114, 0x506aa234);
		odm_write_4byte(dm, 0x4118, 0x000004ff);
#if 0
		odm_write_4byte(dm, 0x41b0, 0x0809fb09);
		odm_write_4byte(dm, 0x41b4, 0x00000000);
		odm_write_4byte(dm, 0x41bc, 0x00c3ff80);
		odm_write_4byte(dm, 0x41c0, 0x0002c100);
		odm_write_4byte(dm, 0x41c4, 0x00000004);
		odm_write_4byte(dm, 0x41c8, 0x001fffe0);
#endif
		odm_write_4byte(dm, 0x5210, 0x0005c304);
		odm_write_4byte(dm, 0x5214, 0x506aa234);
		odm_write_4byte(dm, 0x5218, 0x000004ff);
#if 0
		odm_write_4byte(dm, 0x52b0, 0x0809fb09);
		odm_write_4byte(dm, 0x52b4, 0x00000000);
		odm_write_4byte(dm, 0x52bc, 0x00c3ff80);
		odm_write_4byte(dm, 0x52c0, 0x0002c100);
		odm_write_4byte(dm, 0x52c4, 0x00000004);
		odm_write_4byte(dm, 0x52c8, 0x001fffe0);
#endif		
		odm_write_4byte(dm, 0x5310, 0x0005c304);
		odm_write_4byte(dm, 0x5314, 0x506aa234);
		odm_write_4byte(dm, 0x5318, 0x000004ff);
#if 0
		odm_write_4byte(dm, 0x53b0, 0x0809fb09);
		odm_write_4byte(dm, 0x53b4, 0x00000000);
		odm_write_4byte(dm, 0x53bc, 0x00c3ff80);
		odm_write_4byte(dm, 0x53c0, 0x0002c100);
		odm_write_4byte(dm, 0x53c4, 0x00000004);
		odm_write_4byte(dm, 0x53c8, 0x001fffe0);
#endif
	}

}

void _dpk_set_afe_8814b(struct dm_struct *dm, boolean is_do_dpk)
{
	if (is_do_dpk) {
		odm_set_bb_reg(dm, 0x1830, BIT(30), 0x0);
		odm_set_bb_reg(dm, 0x1860, 0xfffff000, 0xf0001);
		odm_set_bb_reg(dm, 0x4130, BIT(30), 0x0);
		odm_set_bb_reg(dm, 0x4160, 0xfffff000, 0xf0001);
		odm_set_bb_reg(dm, 0x5230, BIT(30), 0x0);
		odm_set_bb_reg(dm, 0x5260, 0xfffff000, 0xf0001);
		odm_set_bb_reg(dm, 0x5330, BIT(30), 0x0);
		odm_set_bb_reg(dm, 0x5360, 0xfffff000, 0xf0001);
		/*ADDA FIFO reset*/	
		odm_write_4byte(dm, 0x1c38, 0x0);
		ODM_delay_us(10);
		odm_write_4byte(dm, 0x1c38, 0xffffffff);
	} else {
		odm_set_bb_reg(dm, 0x1830, BIT(30), 0x1);
		odm_set_bb_reg(dm, 0x4130, BIT(30), 0x1);
		odm_set_bb_reg(dm, 0x5230, BIT(30), 0x1);
		odm_set_bb_reg(dm, 0x5330, BIT(30), 0x1);
	}
}

void _dpk_afe_setting_8814b(struct dm_struct *dm, boolean is_do_dpk)
{
	int i;
	RF_DBG(dm, DBG_RF_DPK, "\n");
	if (is_do_dpk) {
		//AFE on Settings//
		_dpk_afe_pre_setting_8814b(dm, true);

		odm_set_bb_reg(dm, 0x1818, BIT(1), 0x1);
		odm_set_bb_reg(dm, 0x4118, BIT(1), 0x1);
		odm_set_bb_reg(dm, 0x5218, BIT(1), 0x1);		
		odm_set_bb_reg(dm, 0x5318, BIT(1), 0x1);

		odm_write_4byte(dm, 0x1830, 0x700f0041);
		for (i = 0; i < 0x10; i++)
			odm_write_4byte(dm, 0x1830, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x1830, 0x70ff0041);

		odm_write_4byte(dm, 0x4130, 0x700f0041);
		for (i = 0; i < 0x10; i++)
			odm_write_4byte(dm, 0x4130, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x4130, 0x70ff0041);


		odm_write_4byte(dm, 0x5230, 0x700f0041);
		for (i = 0; i < 0x10; i++)
			odm_write_4byte(dm, 0x5230, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x5230, 0x70ff0041);

		odm_write_4byte(dm, 0x5330, 0x700f0041);
		for (i = 0; i < 0x10; i++)
			odm_write_4byte(dm, 0x5330, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x5330, 0x70ff0041);
	} else {
		odm_write_4byte(dm, 0x1830, 0x700b8001);
		odm_write_4byte(dm, 0x1830, 0x700b8001);
		odm_write_4byte(dm, 0x1830, 0x70144001);
		odm_write_4byte(dm, 0x1830, 0x70244001);
		odm_write_4byte(dm, 0x1830, 0x70344001);
		odm_write_4byte(dm, 0x1830, 0x70444001);
		odm_write_4byte(dm, 0x1830, 0x705b8001);
		odm_write_4byte(dm, 0x1830, 0x70644001);
		odm_write_4byte(dm, 0x1830, 0x707b8001);
		odm_write_4byte(dm, 0x1830, 0x708b8001);
		odm_write_4byte(dm, 0x1830, 0x709b8001);
		odm_write_4byte(dm, 0x1830, 0x70ab8001);
		odm_write_4byte(dm, 0x1830, 0x70bb8001);
		odm_write_4byte(dm, 0x1830, 0x70cb8001);
		odm_write_4byte(dm, 0x1830, 0x70db8001);
		odm_write_4byte(dm, 0x1830, 0x70eb8001);
		odm_write_4byte(dm, 0x1830, 0x70fb8001);
		odm_write_4byte(dm, 0x1830, 0x70fb8001);
		odm_write_4byte(dm, 0x1830, 0x704f0001);
		odm_write_4byte(dm, 0x4130, 0x700b8001);
		odm_write_4byte(dm, 0x4130, 0x700b8001);
		odm_write_4byte(dm, 0x4130, 0x70144001);
		odm_write_4byte(dm, 0x4130, 0x70244001);
		odm_write_4byte(dm, 0x4130, 0x70344001);
		odm_write_4byte(dm, 0x4130, 0x70444001);
		odm_write_4byte(dm, 0x4130, 0x705b8001);
		odm_write_4byte(dm, 0x4130, 0x70644001);
		odm_write_4byte(dm, 0x4130, 0x707b8001);
		odm_write_4byte(dm, 0x4130, 0x708b8001);
		odm_write_4byte(dm, 0x4130, 0x709b8001);
		odm_write_4byte(dm, 0x4130, 0x70ab8001);
		odm_write_4byte(dm, 0x4130, 0x70bb8001);
		odm_write_4byte(dm, 0x4130, 0x70cb8001);
		odm_write_4byte(dm, 0x4130, 0x70db8001);
		odm_write_4byte(dm, 0x4130, 0x70eb8001);
		odm_write_4byte(dm, 0x4130, 0x70fb8001);
		odm_write_4byte(dm, 0x4130, 0x70fb8001);
		odm_write_4byte(dm, 0x4130, 0x704f0001);	
		odm_write_4byte(dm, 0x5230, 0x700b8001);
		odm_write_4byte(dm, 0x5230, 0x700b8001);
		odm_write_4byte(dm, 0x5230, 0x70144001);
		odm_write_4byte(dm, 0x5230, 0x70244001);
		odm_write_4byte(dm, 0x5230, 0x70344001);
		odm_write_4byte(dm, 0x5230, 0x70444001);
		odm_write_4byte(dm, 0x5230, 0x705b8001);
		odm_write_4byte(dm, 0x5230, 0x70644001);
		odm_write_4byte(dm, 0x5230, 0x707b8001);
		odm_write_4byte(dm, 0x5230, 0x708b8001);
		odm_write_4byte(dm, 0x5230, 0x709b8001);
		odm_write_4byte(dm, 0x5230, 0x70ab8001);
		odm_write_4byte(dm, 0x5230, 0x70bb8001);
		odm_write_4byte(dm, 0x5230, 0x70cb8001);
		odm_write_4byte(dm, 0x5230, 0x70db8001);
		odm_write_4byte(dm, 0x5230, 0x70eb8001);
		odm_write_4byte(dm, 0x5230, 0x70fb8001);
		odm_write_4byte(dm, 0x5230, 0x70fb8001);
		odm_write_4byte(dm, 0x5230, 0x704f0001);
		odm_write_4byte(dm, 0x5330, 0x700b8001);
		odm_write_4byte(dm, 0x5330, 0x700b8001);
		odm_write_4byte(dm, 0x5330, 0x70144001);
		odm_write_4byte(dm, 0x5330, 0x70244001);
		odm_write_4byte(dm, 0x5330, 0x70344001);
		odm_write_4byte(dm, 0x5330, 0x70444001);
		odm_write_4byte(dm, 0x5330, 0x705b8001);
		odm_write_4byte(dm, 0x5330, 0x70644001);
		odm_write_4byte(dm, 0x5330, 0x707b8001);
		odm_write_4byte(dm, 0x5330, 0x708b8001);
		odm_write_4byte(dm, 0x5330, 0x709b8001);
		odm_write_4byte(dm, 0x5330, 0x70ab8001);
		odm_write_4byte(dm, 0x5330, 0x70bb8001);
		odm_write_4byte(dm, 0x5330, 0x70cb8001);
		odm_write_4byte(dm, 0x5330, 0x70db8001);
		odm_write_4byte(dm, 0x5330, 0x70eb8001);
		odm_write_4byte(dm, 0x5330, 0x70fb8001);
		odm_write_4byte(dm, 0x5330, 0x70fb8001);
		odm_write_4byte(dm, 0x5330, 0x704f0001);
	}
}

void _dpk_con_tx_8814b(struct dm_struct *dm, boolean is_contx)
{
#if 0
	if (is_contx) {
		/*block ODFM signal due to contx to observe ramp siganl*/
		odm_set_bb_reg(dm, R_0x800, BIT(31), 0x1);
		odm_set_bb_reg(dm, R_0x1d08, BIT(0), 0x1);
		odm_set_bb_reg(dm, R_0x1ca4, BIT(0), 0x1);
		odm_set_bb_reg(dm, R_0x1e70, BIT(1), 0x1);
		odm_set_bb_reg(dm, R_0x1e70, BIT(1), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x1);

		RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK con_tx on!!!\n");
	} else {
		/*restore ODFM signal*/
		odm_set_bb_reg(dm, R_0x800, BIT(31), 0x0);
		odm_set_bb_reg(dm, R_0x1d08, BIT(0), 0x0);
		odm_set_bb_reg(dm, R_0x1e70, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x1ca4, BIT(0), 0x0);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK con_tx off!!!\n");
	}
#endif
}

void _dpk_set_group_8814b(struct dm_struct *dm, u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
#if 1
	switch (group) {
		case 0: /*channel 3*/
			config_phydm_switch_channel_8814b(dm, 1);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x3c03);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to 20M-CH7\n");*/
			break;
		case 1: /*channel 7*/
			config_phydm_switch_channel_8814b(dm, 5);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x3c07);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to 20M-CH7\n");*/
			break;
		case 2: /*channel 11*/
			config_phydm_switch_channel_8814b(dm, 11);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x3c0b);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switchto 20M-CH11\n");*/
			break;
		case 3: /*channe48 bw20*/
			/*config_phydm_switch_channel_8814b(dm, 48);*/			
			config_phydm_switch_channel_8814b(dm, 36);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0xd30);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH36\n");
			break;
		case 4: /*channel120 bw20*/
			config_phydm_switch_channel_8814b(dm, 100);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0xd78);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH120\n");*/
			break;
		case 5: /*channel157 bw20*/
			config_phydm_switch_channel_8814b(dm, 157);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x0);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0xd9d);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH157\n");*/
			break;
		case 6: /*channe58 bw80*/
			config_phydm_switch_channel_8814b(dm, 42);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x2);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x53a);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH58\n");*/
			break;
		case 7: /*channel122 bw80*/
			config_phydm_switch_channel_8814b(dm, 106);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x2);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x57a);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH122\n");*/
			break;
		case 8: /*channel155 bw80*/
			config_phydm_switch_channel_8814b(dm, 171);
			config_phydm_switch_bw_8814b(dm, 0x1, 0x2);
			//odm_set_rf_reg(dm, 0x0, RF_0x18, 0x07fff, 0x59b);
			/*RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to CH155\n");*/
			break;
		}

	RF_DBG(dm, DBG_RF_DPK, "[DPK][SetGroup]S%d, group=%x, RF_0x18 = 0x%x\n",
	       RF_PATH_A, group,
	       odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK));
#endif
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to group%d, RF0x18 = 0x%x\n",
	       group, odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK));
#endif
}


u8 _dpk_pas_gain_check_8814b(struct dm_struct *dm, u8 path)
{

	u8 result = 0x0;
	u32 i_val = 0, q_val = 0;
#if 0
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);

	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e03f);
	//odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00290000);
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00090000);

	i_val = odm_get_bb_reg(dm, R_0x1bfc, MASKHWORD);
	q_val = odm_get_bb_reg(dm, R_0x1bfc, MASKLWORD);

	if (i_val >> 15 != 0)
		i_val = 0x10000 - i_val;
	if (q_val >> 15 != 0)
		q_val = 0x10000 - q_val;

	if ((i_val * i_val + q_val * q_val) > 0x11f3ca) {
		/*PA scan > 0.5dB happen*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] PA scan > 0.5dB happen!!\n");
		result = 1;
	} else {
		result = 0;
	}
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x1);
#endif
	return result;
}


u8 _dpk_gainloss_8814b(struct dm_struct *dm, u8 path)
{
	u8 k = 0x0, tx_agc_search = 0x0, result[5] = {0x0, 0x0, 0x0, 0x0, 0x0};
	s8 txidx_offset = 0x0;
	u8 i = 0x0;
	boolean log_result;

#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][GS] %s\n",__func__);
	if (path == 0x3)
		log_result = _dpk_deb_log_8814b(dm);
#endif

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_1byte(dm, 0x1b49, 0x0);

	for (k = 0; k < 1; k++) {
		_dpk_one_shot_8814b(dm, path, 0x0);		
		odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | 0x8);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00060001);
		odm_set_bb_reg(dm, R_0x1b4c, MASKDWORD, 0x00000000);
		odm_write_1byte(dm, 0x1b49, 0x40);
		result[k] = (u8)((odm_read_1byte(dm, R_0x1bfc) & 0xf0) >> 4);
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] result[%d] = 0x%x\n",
		       k, result[k]);
	}
	tx_agc_search = result[0];

	RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] TXAGC_search_S%d = 0x%x\n",
	       path, tx_agc_search);

	odm_write_1byte(dm, 0x1b49, 0x00);

	if (DPK_PAS_DBG_8814B)
		_dpk_pas_gl_read_8814b(dm, path); 

	return tx_agc_search;
}

boolean _dpk_by_path_8814b(struct dm_struct *dm, u8 tx_agc_search, u8 path,
		       u8 group)
{
	u8 reg_1b67;
	u8 tx_agc = 0x0, result = 1;
	u32 tx_agc_ori = 0x0;
	u8 tmp, i;
	u8 rf_0x56 = 0x0;
	boolean log_result;

	tx_agc_ori = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f);

	tmp = (u8)(tx_agc_ori & 0x1f);

	tx_agc =  tmp - tx_agc_search;

	reg_1b67 = tx_agc;

#if 1

	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK,
		       (0x50000 | tx_agc));
	ODM_delay_us(50);

	rf_0x56 = (u8) odm_get_rf_reg(dm, (enum rf_path)path, RF_0x56, 0x0001f);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] original 0x1b67 = 0x%x\n", reg_1b67);
	RF_DBG(dm, DBG_RF_DPK, "\n");
	if (dm->cut_version < 0x2) {
		if (rf_0x56 == 0xd) {
			reg_1b67++;
			tx_agc++;
			rf_56_txbb_flag = true;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] rf_0x56[4:0] == 0xd \n");		
			RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] 0x1b67++ = 0x%x\n", reg_1b67);
		} else {
			rf_56_txbb_flag = false;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] rf_0x56[4:0]=%d \n", rf_0x56);	
		}
	}
#endif
#if 1
	if (*dm->band_type == ODM_BAND_5G) {
		if ((*dm->band_width == 2) ){			
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][DO_DPK] 0x1b67 = 0x%x\n", reg_1b67);
			reg_1b67 = reg_1b67 + 1;			
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][DO_DPK] do 80MHz DPK\n");
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][DO_DPK] 0x1b67 + 1 = 0x%x\n", reg_1b67);			
		} else if ( *dm->band_width == 1) {
			reg_1b67 = reg_1b67 + 1;			
			RF_DBG(dm, DBG_RF_DPK,
		  	     "[DPK][DO_DPK] do 40MHz DPK\n");
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][DO_DPK] 0x1b67 + 1 = 0x%x\n", reg_1b67);			
		}
	}	
	RF_DBG(dm, DBG_RF_DPK, "\n");
#endif

	/*TXAGC for DPK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK,
		       (0x50000 | tx_agc));
	ODM_delay_us(50);

	//reg_1b67 = pwsf_idx & 0x1f;
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_1byte(dm, R_0x1b67, reg_1b67);
	odm_write_1byte(dm, 0x1b49, 0x0);
	odm_set_bb_reg(dm, 0x1b40, 0xffff0000, 0x2000);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][DO_DPK] tx_agc=0x%x,rf0=%x,0x1b40=0x%x\n",
	       tx_agc, tx_agc_ori, odm_read_4byte(dm, R_0x1b40));
	
	result = _dpk_one_shot_8814b(dm, path, 0x1);
	odm_write_1byte(dm, 0x1b49, 0x0);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK]S%d fail bit = %x\n", path, result);

	if (DPK_PAS_DBG_8814B)
		_dpk_pas_dpk_read_8814b(dm, path);

	return result;
 
}

boolean _dpk_iq_check_8814b(struct dm_struct *dm, u8 addr, u32 reg_1bfc)
{
	u32 i_val = 0, q_val = 0;

	return 0;
#if 0
	if (DPK_SRAM_IQ_DBG_8814B && addr < 16)
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] 0x1bfc[%2d] = 0x%x\n", addr, reg_1bfc);

	i_val = (reg_1bfc & 0x003FF800) >> 11;
		q_val = reg_1bfc & 0x000007FF;

		if (((q_val & 0x400) >> 10) == 1)
			q_val = 0x800 - q_val;

	if (addr == 0 && ((i_val * i_val + q_val * q_val) < 0x2851e)) {
		/* LMS (I^2 + Q^2) < -2dB happen*/
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT < -2dB happen, I=0x%x, Q=0x%x\n",
			       i_val, q_val);
			return 1;
	} else if ((i_val * i_val + q_val * q_val) > 0x47cf2) {
		/* LMS (I^2 + Q^2) > 0.5dB happen*/
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT > 0.5dB happen, I=0x%x, Q=0x%x\n",
		       i_val, q_val);
		return 1;
	} else {
		return 0;
	}
#endif
}

void _dpk_on_8814b(struct dm_struct *dm, u8 path)
{
	u8 i = 0x0;
	boolean log_result;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 rf_0x56 = 0x0;

#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_ON] %s\n",__func__);
	if (path == 0x3)
		log_result = _dpk_deb_log_8814b(dm);
#endif

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_write_1byte(dm, 0x1b54, 0x01);	
	odm_write_1byte(dm, 0x1b59, 0x88);

	if (rf_56_txbb_flag == true) {
		odm_set_bb_reg(dm, 0x1b54, 0x001fff00, 0x169a); //3dB		
		RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_ON] 1b54=0x169a\n");
	}
	else {
		odm_set_bb_reg(dm, 0x1b54, 0x001fff00, 0x1425); //2dB		
		RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_ON] 1b54=0x1425\n");
	}
	odm_write_1byte(dm, 0x1b58, 0x00);
	odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x0);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_ON]S%d DPD enable!!!\n\n", path);
}



boolean _dpk_lut_sram_read_8814b(void *dm_void, u8 group, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 i;
	u32 reg_1b58 = 0, reg_1bfc = 0;
	boolean result = true;

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	odm_set_bb_reg(dm, 0x1b54, BIT(1), 0x0);
	odm_write_4byte(dm, 0x1bd4, 0x00260001);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]group= 0x%x, path = 0x%x\n",
	       group, path);
/*
	for (i = 0; i <  0x100/4; i++)
		RF_DBG(dm, DBG_RF_DPK, "[DPK] (1) 1b%x = 0x%x\n",
		       i*4, odm_read_4byte(dm, (0x1b00 + i*4)));
*/

	for (i = 0; i < 64; i++) {
		odm_write_4byte(dm, R_0x1b58, 0x00388800 | i << 24);
		reg_1b58 = odm_read_4byte(dm, R_0x1b58);
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
/*
		RF_DBG(dm, DBG_RF_DPK, "[DPK]1b58 = 0x%x, 1bfc = 0x%x\n",
		       reg_1b58, reg_1bfc);
*/
		if (group < G_2G_N)
			dpk_info->lut_2g[path][group][i] = reg_1bfc;
		else
			dpk_info->lut_5g[path][group - G_2G_N][i] = reg_1bfc;
	}
	odm_write_4byte(dm, 0x1b58, 0x00000000);
#if DPK_PAS_DBG_8814B
	for (i = 0; i < 64; i++) {
		if (group < G_2G_N)
			RF_DBG(dm, DBG_RF_DPK, "[DPK]2g[%x][%x][%x] = 0x%x\n",
			       path, group, i,
			       dpk_info->lut_2g[path][group][i]);
		else
			RF_DBG(dm, DBG_RF_DPK, "[DPK]5g[%x][%x][%x] = 0x%x\n",
			       path, group - G_2G_N, i,
			       dpk_info->lut_5g[path][group - G_2G_N][i]);
	}
#endif
	return result;
}

void _dpk_lut_sram_write_8814b(void *dm_void, u8 group, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 i;
	u32 reg_1b5c, tmp;

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);	
	odm_write_1byte(dm, 0x1b54, 0x0);
	odm_write_4byte(dm, 0x1bd4, 0x00260001);
	for (i = 0; i < 64; i++) {
		if (group < G_2G_N)
			tmp = dpk_info->lut_2g[path][group][i];
		else
			tmp = dpk_info->lut_5g[path][group - G_2G_N][i];
		odm_write_4byte(dm, R_0x1b58, 0x00B88800 | i << 24 );
		odm_write_4byte(dm, R_0x1b5c, tmp);		
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK]W S%d[%d]sram[%d]= 0x%x\n",
		path, group, i, tmp);
#endif
	}
	odm_write_4byte(dm, R_0x1b58, 0x0);
	odm_write_4byte(dm, R_0x1b5c, 0x0);
}

boolean _dpk_check_fail_8814b(struct dm_struct *dm, boolean is_fail, u8 path,
			 u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 reg1b67 = 0x0;

	boolean fail = true;
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);

#if 1 //  if antenna is not connected, reg1b67 < 0x12
	reg1b67 = odm_read_1byte(dm, R_0x1b67);
	if (reg1b67 <= 0x12)
		is_fail = true;
#endif
	if (!is_fail) {
		if (_dpk_lut_sram_read_8814b(dm, group, path)) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] = S%d[%d] sram read PASS =\n",
			       path, group);
			if (group < 3) {
				dpk_info->pwsf_2g[path][group] =
				odm_read_1byte(dm, R_0x1b67);
				dpk_info->dpk_result[path][group] = 1;
			} else {
				dpk_info->pwsf_5g[path][group - G_2G_N] =
					odm_read_1byte(dm, R_0x1b67);
				dpk_info->dpk_5g_result[path][group - G_2G_N] =
									      1;
			}
			fail = false;
		} else {
			if (group < 3) {
				dpk_info->pwsf_2g[path][group] = 0;
				dpk_info->dpk_result[path][group] = 0;
			} else {
				dpk_info->pwsf_5g[path][group - G_2G_N] = 0;
				dpk_info->dpk_5g_result[path][group - G_2G_N] =
									      0;
			}
			fail = false;
		}
	} else {
		dpk_info->pwsf_2g[path][group] = 0;
		dpk_info->pwsf_5g[path][group - G_2G_N] = 0;
		dpk_info->dpk_result[path][group] = 0;
		dpk_info->dpk_5g_result[path][group - G_2G_N] = 0;
		fail = true;
	}
	return fail;
}

void _dpk_result_reset_8814b(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path = 0x0, group = 0x0, i;

	/*dpk_info->is_dpk_path_ok[path] = 0;*/
	dpk_info->dpk_path_ok = 0;

	for (path = 0; path < DPK_RF_PATH_NUM_8814B; path++) {
		for (group = 0; group < G_2G_N; group++) {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_result[path][group] = 0;
		}
		for (group = 0; group < G_5G_N; group++) {
			dpk_info->pwsf_5g[path][group] = 0;
			dpk_info->dpk_5g_result[path][group] = 0;

		}
	}
	_dpk_clear_lut_table_8814b(dm);
}

void _dpk_calibrate_8814b(struct dm_struct *dm, u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 dpk_fail = 1, tx_agc_search = 0;
	u8 group, retry_cnt, result;
	boolean is_2g_fail = false;
	boolean is_5g_fail = false;

	_dpk_rfsetting_8814b(dm, path);
	//for (group = 0; group < DPK_GROUP_NUM_8814B; group++) {	
	for (group = 0; group < 1; group++) {
		_dpk_set_group_8814b(dm, 0x3);

		RF_DBG(dm, DBG_RF_DPK, "\n");
		//for (retry_cnt = 0; retry_cnt < 6; retry_cnt++) {
		for (retry_cnt = 0; retry_cnt < 1; retry_cnt++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK]Group %d retry =%d\n", group, retry_cnt);
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] = S%d[%d] DPK Start =\n", path, group);
			//ODM_delay_ms(1);
			tx_agc_search = _dpk_gainloss_8814b(dm, path);
			//ODM_delay_ms(1);
			dpk_fail = _dpk_by_path_8814b(dm, tx_agc_search,
						      path, group);
			dpk_fail = false;
			//RF_DBG(dm, DBG_RF_DPK,
			//       "[DPK] = S%d[%d] DPK Finish =\n", path, group);
			result =
			_dpk_check_fail_8814b(dm, dpk_fail, path, group);
			if (result)
				break;
		}
		RF_DBG(dm, DBG_RF_DPK, "\n");
	}

	for (group = 0; group < G_2G_N; group++) {
		if (dpk_info->dpk_result[path][group] == 0x0) {
			is_2g_fail = true;
			break;
		}
	}

	for (group = G_2G_N; group < DPK_GROUP_NUM_8814B; group++) {
		if (dpk_info->dpk_5g_result[path][group - G_2G_N] == 0x0) {
			is_5g_fail = true;
			break;
		}
	}
	if (!(is_2g_fail || is_5g_fail))
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);
	if (dpk_info->dpk_path_ok > 0)
		dpk_info->is_dpk_enable = 1;
	
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] = S%d[%d] DPK Finish =\n", path, group);
return;
}

void _dpk_enable_disable_8814b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);
	if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
		if (dpk_info->is_dpk_enable) {
			odm_set_bb_reg(dm, R_0x1b54, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x0);
			
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK enable\n", path);
		} else {
			odm_set_bb_reg(dm, R_0x1b54, BIT(0), 0x0);			
			odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x1);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK bypass\n", path);
		}
	}
}

void _dpk_reload_8814b(void *dm_void, u8 group, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	_dpk_lut_sram_write_8814b(dm, group, path);

	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | path << 1);

	if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK reload Pass\n", path);
		_dpk_on_8814b(dm, path);
	} else {
		odm_set_bb_reg(dm, R_0x1b54, BIT(0), 0x0);
		odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x1);		
		RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK reload Fail\n", path);
	}
	odm_set_bb_reg(dm, R_0x1b20, BIT(26), 0x1); //enable iqk
	odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0xf0000, 0x3);	
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_ON]S%d into RX mode\n", path);	
	RF_DBG(dm, DBG_RF_DPK, "\n");
	//_dpk_enable_disable_8814b(dm, path);
}



void _dpk_thermal_read_8814b(
	void *dm_void,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x1);
	ODM_delay_us(50);

	dpk_info->thermal_dpk[path] = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
							 0x42, 0x0FC00) - 0x2;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] thermal S%d = %d\n", path,
	       dpk_info->thermal_dpk[path]);
}


void _dpk_thermal_read_dbg_8814b(
	void *dm_void,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 tmp = 0x0;

	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, 0x42, BIT(17), 0x1);
	ODM_delay_us(50);

	tmp = (u8)odm_get_rf_reg(dm, (enum rf_path)path, 0x42, 0x0FC00);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] thermal dbg S%d = %d\n", path, tmp);
}

void dpk_thermal_read_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path = 0x0;

	for (path = 0; path < 4; path++)
		_dpk_thermal_read_8814b(dm, path);
}


void _dpk_path_select_8814b(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

#if (DPK_DO_PATH_A)
	_dpk_calibrate_8814b(dm, RF_PATH_A);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_A)) >> RF_PATH_A)
		_dpk_on_8814b(dm, RF_PATH_A);
#endif

#if (DPK_DO_PATH_B)
	_dpk_calibrate_8814b(dm, RF_PATH_B);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_B)) >> RF_PATH_B)
	_dpk_on_8814b(dm, RF_PATH_B);
#endif

#if (DPK_DO_PATH_C)
	_dpk_calibrate_8814b(dm, RF_PATH_C);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_C)) >> RF_PATH_C)
	_dpk_on_8814b(dm, RF_PATH_C);
#endif

#if (DPK_DO_PATH_D)
	_dpk_calibrate_8814b(dm, RF_PATH_D);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_D)) >> RF_PATH_D)
	_dpk_on_8814b(dm, RF_PATH_D);
#endif



}

u8 dpk_channel_transfer_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 channel, bandwidth, i = 0x3;

	channel = *dm->channel;
	bandwidth = *dm->band_width;

	if (*dm->band_type == ODM_BAND_2_4G) {
		if (channel <= 4)
			i = 0;
		else if (channel >= 5 && channel <= 8)
			i = 1;
		else if (channel >= 9)
			i = 2;
	} else {
		if (bandwidth <= 0x1) { //BW20//BW40
			if (channel <= 64)
				i = 3;
			else if (channel >= 45 && channel <= 149)
				i = 4;
			else if (channel >= 150)
				i = 5;
		} else if (bandwidth == 0x2) { //BW80
			if (channel <= 58)
				i = 6;
			else if (channel >= 59 && channel <= 138)
				i = 7;
			else if (channel >= 139)
				i = 8;
		}
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] channel = %d, bandwidth = %d, group = %d\n",
	       channel, bandwidth, i);

	return i;
}

void dpk_sram_read_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, addr;
	u32 tmp1 = 0x0;
	u8 tmp5 = G_2G_N;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Start =========\n");
	path = 0x0;
	for (group = 0; group < DPK_GROUP_NUM_8814B; group++) {
		for (addr = 0; addr < 64; addr++) {
			if (group < 3)
				tmp1 = dpk_info->lut_2g[path][group][addr];
			else
				tmp1 =
				dpk_info->lut_5g[path][group - G_2G_N][addr];
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Read 2G S%d[%d]even[%2d]= 0x%x\n",
			       path, group, addr, tmp1);
			}
		}
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ===== SRAM Read Finish =====\n");
}

void dpk_enable_disable_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path =0x0;

	for(path = 0x0; path < 4; path++)
		_dpk_enable_disable_8814b(dm, path);
}

void dpk_result_summary_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path, group;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8814B; path++) {
		for (group = 0; group < G_2G_N; group++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK]S%d[%d]2Gpwsf= 0x%x, dpk_result[%x]= %d\n",
			       path, group, dpk_info->pwsf_2g[path][group],
			       group, dpk_info->dpk_result[path][group]);
		}
		for (group = G_2G_N; group < DPK_GROUP_NUM_8814B; group++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK]S%d[%d]5Gpwsf= 0x%x, dpk_result[%x]= %d\n",
			       path, group,
			       dpk_info->pwsf_5g[path][group - G_2G_N], group,
			       dpk_info->dpk_5g_result[path][group - G_2G_N]);
		}

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] S%d DPK is %s\n", path,
		       ((dpk_info->dpk_path_ok & BIT(path)) >> path) ?
		       "Success" : "Fail");
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] dpk_path_ok = 0x%x, dpk_result = %d\n",
	       dpk_info->dpk_path_ok, dpk_info->is_dpk_enable);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

#if (DPK_SRAM_read_DBG_8814B)
	dpk_sram_read_8814b(dm);
#endif
}

void dpk_reload_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path = 0x0, group = 0x0;

	group = dpk_channel_transfer_8814b(dm);
	for (path = 0x0; path < 4; path++){
		_dpk_reload_8814b(dm, group, path);
		_dpk_enable_disable_8814b(dm, path);
	}
}


boolean _do_dpk_8814b(void *dm_void)
{

	u32 mac_bp[DPK_MAC_NUM_8814B], bb_bp[DPK_BB_NUM_8814B];
	u32 rf_bp[DPK_RF_NUM_8814B][SS_8814B];
	u32 bp_mac_reg[DPK_MAC_NUM_8814B] = {0x520};
	u32 bp_bb_reg[DPK_BB_NUM_8814B] = {0x1c38, 0x1d58, 0x1d60, 0x180c, 0x410c,
				       0x520c, 0x530c, 0x1d70, 0x1a00, 0x824,
				       0x1a14, 0x1830, 0x4130, 0x5230, 0x5330,
				       0x1860, 0x4160, 0x5260, 0x5360};
	u32 bp_rf_reg[DPK_RF_NUM_8814B] = {0x88, 0x8c, 0x8e, 0xde};
	u8 path = 0x0, retry_cnt = 0, tx_agc_search, k, dpk_step = 0x0;
	u8 gsk1_retry_count = 0x0, gsk3_retry_count = 0x0, gl_retry_count = 0x0;
	u16 i;
	boolean returnflag = false, KFAIL = true, gonext = false;
	static boolean do_clear = true;
	u32 rf0 = 0x0;
	boolean log_result = true;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->dpk_path_ok = 0x0;

	k = dpk_channel_transfer_8814b(dm);

	_dpk_bp_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg, bp_bb_reg);
	_dpk_bp_rf_8814b(dm, rf_bp, bp_rf_reg);

	_dpk_mac_bb_setting_8814b(dm);

	_dpk_manual_txagc_8814b(dm, true);
	
	_dpk_con_tx_8814b(dm, true);

	//_dpk_init_8814b(dm, true);

	//_dpk_afe_setting_8814b(dm, true);
	_dpk_set_afe_8814b(dm, true);

	_dpk_rfe_setting_8814b(dm); // for type 3
		
#if 1
	for (path = 0; path < SS_8814B; path++) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK process start v08\n", path);
		_dpk_rfsetting_8814b(dm, path);
		gonext = true;
		dpk_step = 0x0;
		odm_set_bb_reg(dm, 0x1b20, BIT(26), 0x0);
		odm_set_bb_reg(dm, 0x1b20, BIT(25), 0x0);
		//RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b20 = 0x%x\n", odm_read_4byte(dm, 0x1b20));
		//RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1b34 = 0x%x\n", odm_read_4byte(dm, 0x1b34));		
		do {
#if 1
		switch(dpk_step) {
		case 0:
#if 1
			gonext = false;
			gsk3_retry_count = 0x0;
			while (1) {
				KFAIL = _dpk_pas_agc_8814b(dm, path, GSK3);
				if (DPK_PAS_DBG_8814B)
					_dpk_pas_gl_read_8814b(dm, path); 
				if (KFAIL && (gsk3_retry_count < 2))
					gsk3_retry_count++;
				else if (KFAIL) {
					//dpk_step = 5;
					gonext = true;
				} else {
					dpk_step++;
					gonext = true;
				}
				if (gonext)
					break;
			}
#else
			KFAIL = _dpk_pas_agc_8814b(dm, path, GSK3);
			KFAIL = _dpk_pas_agc_8814b(dm, path, GSK1);
			dpk_step++;
			gonext = true;
#endif
 			break;
		case 1:	
#if 1
		
			gonext = false;
			gsk1_retry_count = 0x0;
			while (1) {
				KFAIL = _dpk_pas_agc_8814b(dm, path, GSK1);
				if (DPK_PAS_DBG_8814B)
					_dpk_pas_gl_read_8814b(dm, path); 
				if (KFAIL && (gsk1_retry_count < 4))
					gsk1_retry_count++;
				else if (KFAIL) {
					dpk_step = 5;
					gonext = true;
				} else {
					dpk_step++;
					gonext = true;
				}
				if (gonext)
					break;
			}
#else
			dpk_step++;
			gonext = true;
#endif
			break;
		case 2:	
#if 1
			gonext = true;
			dpk_info->tx_gain = _dpk_gainloss_8814b(dm, path);
			dpk_step++;
			gl_retry_count++;
#else
			dpk_step++;
			gonext = true;
#endif
			break;
		case 3:	
#if 1
			KFAIL = _dpk_by_path_8814b(dm, dpk_info->tx_gain, path, 0);			
			//KFAIL = !KFAIL;
			dpk_step++;			
			gonext = true;
#else
			dpk_step++;
			gonext = true;
#endif
			break;
		case 4:
#if 1
			KFAIL = _dpk_check_fail_8814b(dm, KFAIL, path, k);	
			dpk_step++;			
			gonext = true;
#else
			dpk_step++;
			gonext = true;
#endif

			break;
		case 5:
			gonext = false;
			break;
		}
#endif
		if (dpk_step == 5) {
			if (!KFAIL) {				
				dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);
				dpk_info->is_dpk_enable = true;
			} else {			
				dpk_info->dpk_path_ok = dpk_info->dpk_path_ok & ~BIT(path);
				dpk_info->is_dpk_enable = false;
			}
			for (i = 0; i < SS_8814B; i++) {
				odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | i << 1);
				odm_write_1byte(dm, 0x1bcc, 0x0);
			}	
		_dpk_reload_8814b(dm, k, path);
		gonext = false;
		}
		
	} while (gonext);
	}
#endif
	dpk_thermal_read_8814b(dm);

	//_dpk_afe_setting_8814b(dm, false);
	
	_dpk_set_afe_8814b(dm, false);

	_dpk_init_8814b(dm, false);

	_dpk_con_tx_8814b(dm, false);

	_dpk_manual_txagc_8814b(dm, false);

#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_FINISH] %s\n",__func__);
	path =0x3; 
	if (path == 0x3)
		log_result = _dpk_deb_log_8814b(dm);
#endif

	_dpk_reload_macbb_8814b(dm, mac_bp, bb_bp, bp_mac_reg,
				bp_bb_reg);
	_dpk_reload_rf_8814b(dm, bp_rf_reg, rf_bp);
	
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK][DPK_BK] %s\n",__func__);
		path =0x3; 
		if (path == 0x3)
			log_result = _dpk_deb_log_8814b(dm);
#endif

	return false;

}

void do_dpk_8814b(void *dm_void)
{

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	boolean KFail;

	if (dm->ext_pa || dm->ext_pa_5g) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Skip DPK due to ext_PA exist!!\n");
		return;
	} else if (!dpk_info->is_dpk_pwr_on) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Skip DPK due to DPD PWR off !!\n");
		return;
	} else {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK]DPK Start (Ver: %s), Cv: %d, Package: %d, rfe : %d\n",
		       DPK_VER_8814B, dm->cut_version, dm->package_type, dm->rfe_type);
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK]dm->ext_pa : %d, ext_pa_5g : %d\n", dm->ext_pa, dm->ext_pa_5g);		
	}

	if (dpk_get_dpkbychannel_8814b(dm) == false) {
		dpk_by_group_8814b(dm); /*do dpk 9 ch*/
		dpk_result_summary_8814b(dm);
	} else {
		KFail = _do_dpk_8814b(dm); /*do dpk 1 ch*/
	}
}
void dpk_by_group_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	boolean KFail;

#if 0
	// 2.4G band
	*dm->band_type = ODM_BAND_2_4G;
	*dm->band_width = CHANNEL_WIDTH_20;
	config_phydm_switch_band_8814b(dm, 3);
	// 20M bandwidth
	config_phydm_switch_bw_8814b(dm, 0x1, CHANNEL_WIDTH_20);
	// channel 3
	config_phydm_switch_channel_8814b(dm, 3);
	*dm->channel = 3;
	KFail = _do_dpk_8814b(dm);
	// channel 5
	config_phydm_switch_channel_8814b(dm, 5);
	*dm->channel = 5;
	KFail = _do_dpk_8814b(dm);
	// channel 11
	config_phydm_switch_channel_8814b(dm, 11);
	*dm->channel = 11;
	_do_dpk_8814b(dm);
#endif
	// 5G band
	*dm->band_type = ODM_BAND_5G;
	*dm->band_width = CHANNEL_WIDTH_20;
	config_phydm_switch_band_8814b(dm, 48);
	// channel 48
	config_phydm_switch_channel_8814b(dm, 48);
	*dm->channel = 48;
	KFail = _do_dpk_8814b(dm);
	// channel 120
	config_phydm_switch_channel_8814b(dm, 120);
	*dm->channel = 120;
	KFail = _do_dpk_8814b(dm);
	// channel 157
	config_phydm_switch_channel_8814b(dm, 157);
	*dm->channel = 157;
	KFail = _do_dpk_8814b(dm);

	// 80M bandwidth
	*dm->band_type = ODM_BAND_5G;
	*dm->band_width = CHANNEL_WIDTH_80;
	config_phydm_switch_bw_8814b(dm, 0x1, CHANNEL_WIDTH_80);
	// channel 58
	config_phydm_switch_channel_8814b(dm, 58);
	*dm->channel = 58;
	KFail = _do_dpk_8814b(dm);
	// channel 122
	config_phydm_switch_channel_8814b(dm, 122);
	*dm->channel = 122;
	KFail = _do_dpk_8814b(dm);
	// channel 155
	config_phydm_switch_channel_8814b(dm, 155);
	*dm->channel = 155;
	KFail = _do_dpk_8814b(dm);
}

void dpk_track_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	//struct rtl8192cd_priv *priv = dm->priv;

	s8 pwsf_a, pwsf_b, pwsf_c, pwsf_d;
	u8 i = 0, k = 0;
	u8 thermal_dpk_avg_count = 0;
	u8 delta_dpk[4] = {0, 0, 0, 0};
	u8 offset[4] = {0, 0, 0, 0};
	u32 thermal_dpk_avg[4] = {0, 0, 0, 0};
	u8 thermal_value[4] = {0, 0, 0, 0};
	u8 path, pwsf[4] = {0, 0, 0, 0};
	u8 is_increase[4] = {0, 0, 0, 0};
	s8 idx_offset[4] = {0, 0, 0, 0};
	u8 reg1b58[4] = {0, 0, 0, 0};

	//if (rf->eeprom_thermal == 0 || rf->eeprom_thermal > 100)
	//	rf->eeprom_thermal = 25;

	if (dm->ext_pa) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK Track]Skip DPK : ext_PA!!\n");
		return;
	} else if (!dpk_info->is_dpk_pwr_on) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK Track]Skip DPK : DPD PWR off\n");
		return;
	} else {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] ***DPK Start (Ver: %s), Cv: %d, Package: %d**\n",
		       DPK_VER_8814B, dm->cut_version, dm->package_type);
	}

	if (dpk_info->is_dpk_by_channel == false)
		for (i = 0; i < DPK_RF_NUM_8814B; i++)
			dpk_info->thermal_dpk[i] = rf->eeprom_thermal;

	/*thermal meter trigger*//*get thermal meter*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17), 0x1);	
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17), 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17), 0x1);	
	ODM_delay_us(50);
	thermal_value[0] = (u8)odm_get_rf_reg(dm, RF_PATH_A, 0x42, 0xfc00);
	
	odm_set_rf_reg(dm, RF_PATH_B, 0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, RF_PATH_B, 0x42, BIT(17), 0x0);	
	odm_set_rf_reg(dm, RF_PATH_B, 0x42, BIT(17), 0x1);	
	ODM_delay_us(50);
	thermal_value[1] = (u8)odm_get_rf_reg(dm, RF_PATH_B, 0x42, 0xfc00);

	odm_set_rf_reg(dm, RF_PATH_C, 0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, RF_PATH_C, 0x42, BIT(17), 0x0);
	odm_set_rf_reg(dm, RF_PATH_C, 0x42, BIT(17), 0x1);
	ODM_delay_us(50);
	thermal_value[2] = (u8)odm_get_rf_reg(dm, RF_PATH_C, 0x42, 0xfc00);
	
	odm_set_rf_reg(dm, RF_PATH_D, 0x42, BIT(17), 0x1);
	odm_set_rf_reg(dm, RF_PATH_D, 0x42, BIT(17), 0x0);	
	odm_set_rf_reg(dm, RF_PATH_D, 0x42, BIT(17), 0x1);
	ODM_delay_us(50);
	thermal_value[3] = (u8)odm_get_rf_reg(dm, RF_PATH_D, 0x42, 0xfc00);

	/* calculate average thermal meter */
	dpk_info->thermal_dpk_avg[0][dpk_info->thermal_dpk_avg_index] =
		thermal_value[0];	
	dpk_info->thermal_dpk_avg[1][dpk_info->thermal_dpk_avg_index] =
		thermal_value[1];	
	dpk_info->thermal_dpk_avg[2][dpk_info->thermal_dpk_avg_index] =
		thermal_value[2];	
	dpk_info->thermal_dpk_avg[3][dpk_info->thermal_dpk_avg_index] =
		thermal_value[3];
	dpk_info->thermal_dpk_avg_index++;

	/*Average times */
	if (dpk_info->thermal_dpk_avg_index == THERMAL_DPK_AVG_NUM)
		dpk_info->thermal_dpk_avg_index = 0;
	
	for (i = 0; i < THERMAL_DPK_AVG_NUM; i++) {
		if (dpk_info->thermal_dpk_avg[0][i] ||
		    dpk_info->thermal_dpk_avg[1][i] || 
		    dpk_info->thermal_dpk_avg[2][i] ||
		    dpk_info->thermal_dpk_avg[3][i]) {
			thermal_dpk_avg[0] += dpk_info->thermal_dpk_avg[0][i];			
			thermal_dpk_avg[1] += dpk_info->thermal_dpk_avg[1][i];			
			thermal_dpk_avg[2] += dpk_info->thermal_dpk_avg[2][i];			
			thermal_dpk_avg[3] += dpk_info->thermal_dpk_avg[3][i];
			thermal_dpk_avg_count++;
		}
	}

	/*Calculate Average ThermalValue after average enough times*/
	if (thermal_dpk_avg_count) {
	
		thermal_value[0] = (u8)(thermal_dpk_avg[0] / thermal_dpk_avg_count);
		thermal_value[1] = (u8)(thermal_dpk_avg[1] / thermal_dpk_avg_count);
		thermal_value[2] = (u8)(thermal_dpk_avg[2] / thermal_dpk_avg_count);
		thermal_value[3] = (u8)(thermal_dpk_avg[3] / thermal_dpk_avg_count);

		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S0 ThermalValue_DPK_AVG (count) = %d (%d))\n",
		       thermal_dpk_avg[0], thermal_dpk_avg_count);
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S1 ThermalValue_DPK_AVG (count) = %d (%d))\n",
		       thermal_dpk_avg[1], thermal_dpk_avg_count);
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S2 ThermalValue_DPK_AVG (count) = %d (%d))\n",
		       thermal_dpk_avg[2], thermal_dpk_avg_count);
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S3 ThermalValue_DPK_AVG (count) = %d (%d))\n",
		       thermal_dpk_avg[3], thermal_dpk_avg_count);

		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S0 AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value[0], dpk_info->thermal_dpk[0]);		
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S1 AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value[1], dpk_info->thermal_dpk[1]);
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S2 AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value[2], dpk_info->thermal_dpk[2]);
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S3 AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value[3], dpk_info->thermal_dpk[3]);
	}

	delta_dpk[0] = HALRF_ABS(thermal_value[0], dpk_info->thermal_dpk[0]);
	delta_dpk[1] = HALRF_ABS(thermal_value[1], dpk_info->thermal_dpk[1]);	
	delta_dpk[2] = HALRF_ABS(thermal_value[2], dpk_info->thermal_dpk[2]);
	delta_dpk[3] = HALRF_ABS(thermal_value[3], dpk_info->thermal_dpk[3]);

	if (dpk_info->is_dpk_by_channel == true) {
		is_increase[0] = ((thermal_value[0] < dpk_info->thermal_dpk[0]) ? 0 : 1);		
		is_increase[1] = ((thermal_value[1] < dpk_info->thermal_dpk[0]) ? 0 : 1);		
		is_increase[2] = ((thermal_value[2] < dpk_info->thermal_dpk[0]) ? 0 : 1);		
		is_increase[3] = ((thermal_value[3] < dpk_info->thermal_dpk[0]) ? 0 : 1);
	} else {
		is_increase[0] = ((thermal_value[0] < rf->eeprom_thermal) ? 0 : 1);		
		is_increase[1] = ((thermal_value[1] < rf->eeprom_thermal) ? 0 : 1);
		is_increase[2] = ((thermal_value[2] < rf->eeprom_thermal) ? 0 : 1);		
		is_increase[3] =  ((thermal_value[3] < rf->eeprom_thermal) ? 0 : 1);
	}
	offset[0] = (u8) (delta_dpk[0] / DPK_THRESHOLD_8814B);
	offset[1] = (u8) (delta_dpk[1] / DPK_THRESHOLD_8814B);
	offset[2] = (u8) (delta_dpk[2] / DPK_THRESHOLD_8814B);
	offset[3] = (u8) (delta_dpk[3] / DPK_THRESHOLD_8814B);
#if 0
	RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
	       "[DPK_track] S0 delta_DPK=%d, offset=%d, track direction is %s\n",
	       delta_dpk[0], offset[0], (is_increase[0] ? "Plus" : "Minus"));

	RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
	       "[DPK_track] S1 delta_DPK=%d, offset=%d, track direction is %s\n",
	       delta_dpk[1], offset[1], (is_increase[1] ? "Plus" : "Minus"));

	RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
	       "[DPK_track] S2 delta_DPK=%d, offset=%d, track direction is %s\n",
	       delta_dpk[2], offset[2], (is_increase[2] ? "Plus" : "Minus"));

	RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
	       "[DPK_track] S3 delta_DPK=%d, offset=%d, track direction is %s\n",
	       delta_dpk[3], offset[3], (is_increase[3] ? "Plus" : "Minus"));
#endif

	if ( offset[0] == 0x0 && offset[1] == 0x0 && offset[2] == 0x0 && offset[3] == 0x0)
		return;
/*
	if (is_increase) {
		offset[0] = (0x80 - offset[0]) & 0x7f;
		offset[1] = (0x80 - offset[1]) & 0x7f;
	}
*/
	k = dpk_channel_transfer_8814b(dm);

	if (is_increase[0]){
		reg1b58[0] = offset[0];
	} else {
		reg1b58[0] = (0x3f - offset[0] + 1) & 0x3f;
	}

	if (is_increase[1]){
		reg1b58[1] = offset[1];
	} else {
		reg1b58[1] = (0x3f - offset[1] + 1) & 0x3f;
	}

	if (is_increase[2]){
		reg1b58[2] = offset[2];
	} else {
		reg1b58[2] = (0x3f - offset[2] + 1) & 0x3f;
	}

	if (is_increase[3]){
		reg1b58[3] = offset[3];
	} else {
		reg1b58[3] = (0x3f - offset[3] + 1) & 0x3f;
	}
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] offset[0]= 0x%d, direction is %s\n",
	       offset[0], (is_increase[0] ? "Plus" : "Minus"));
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | RF_PATH_A << 1);
	odm_set_bb_reg(dm, R_0x1b58, 0x3f, reg1b58[0]);	

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] offset[1]= 0x%d, direction is %s\n",
	       offset[1], (is_increase[1] ? "Plus" : "Minus"));
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | RF_PATH_B << 1);
	odm_set_bb_reg(dm, R_0x1b58, 0x3f, reg1b58[1]);	
	
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] offset[2]= 0x%d, direction is %s\n",
	       offset[2], (is_increase[2] ? "Plus" : "Minus"));
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | RF_PATH_C << 1);
	odm_set_bb_reg(dm, R_0x1b58, 0x3f, reg1b58[2]);	

	
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] offset[3]= 0x%d, direction is %s\n",
	       offset[3], (is_increase[3] ? "Plus" : "Minus"));
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | RF_PATH_D << 1);
	odm_set_bb_reg(dm, R_0x1b58, 0x3f, reg1b58[3]);

	//return to path A	
	odm_write_4byte(dm, 0x1b00, IQK_CMD_8814B | RF_PATH_A << 1);
	
}

void dpk_set_dpkbychannel_8814b(void *dm_void, boolean dpk_by_ch)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_by_channel = dpk_by_ch;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] set_dpkbychannel_8814b\n");
	return;
}

boolean dpk_get_dpkbychannel_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] get_dpkbychannel_8814b= %x\n",
	       dpk_info->is_dpk_by_channel);

	return dpk_info->is_dpk_by_channel;
}

void dpk_set_is_dpk_enable_8814b(void *dm_void, boolean is_dpk_enable)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_enable = is_dpk_enable;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] set_is_dpk_enable_8814b\n");
	return;
}

boolean dpk_get_is_dpk_enable_8814b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] get_is_dpk_enable_8814b= %x\n",
	       dpk_info->is_dpk_enable);

	return dpk_info->is_dpk_enable;
}

#endif
