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

#if (RTL8195B_SUPPORT == 1)

/*---------------------------Define Local Constant---------------------------*/

/*8195B DPK ver:0x2 20180604*/

boolean
_dpk_check_nctl_done_8195b(struct dm_struct *dm, u8 path, u32 IQK_CMD)
{
	/*this function is only used after the version of nctl8.0*/
	boolean notready = true;
	boolean fail = true;
	u32 delay_count = 0x0;

	while (notready) {
		if (odm_read_1byte(dm, 0x1f7f) == 0x55)
			notready = false;
		else
			notready = true;

		if (notready) {
			/*ODM_sleep_ms(1);*/
			ODM_delay_us(500);
			delay_count++;
		} else {
			fail = (boolean)odm_get_bb_reg(dm, 0x1b08, BIT(26));
			break;
		}
		if (delay_count >= 50) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK]S%d DPK timeout!!!\n",
			       path);
			break;
		}
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	odm_write_1byte(dm, 0x1f7f, 0x0);

	if (!fail)
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK]S%d IQK_CMD =%x, DPK PASS!!!\n", path, IQK_CMD);
	else
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK]S%d IQK_CMD =%x, DPK Fail!!!\n", path, IQK_CMD);
	return fail;
	//return false;
}

u8 _dpk_get_thermal_8195b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x3);
	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x0);
	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x3);
	ODM_delay_us(10);

	dpk_info->thermal_dpk[path] = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
							 RF_0x42, 0x0FC00);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] curr thermal S%d = %d\n", path,
	       dpk_info->thermal_dpk[path]);

	return dpk_info->thermal_dpk[path];
}

void _backup_mac_bb_registers_8195b(struct dm_struct *dm, u32 *reg,
				    u32 *reg_backup,
				    u32 reg_num)
{
	u32 i;

	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = odm_read_4byte(dm, reg[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup MAC/BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _backup_rf_registers_8195b(struct dm_struct *dm, u32 *rf_reg,
				u32 rf_reg_backup[][1])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8195B; i++) {
		rf_reg_backup[i][RF_PATH_A] =
			odm_get_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
#endif
	}
}

void _reload_mac_bb_registers_8195b(struct dm_struct *dm, u32 *reg,
				    u32 *reg_backup, u32 reg_num)

{
	u32 i;

	for (i = 0; i < reg_num; i++) {
		odm_write_4byte(dm, reg[i], reg_backup[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload MAC/BB 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _reload_rf_registers_8195b(struct dm_struct *dm, u32 *rf_reg,
				u32 rf_reg_backup[][1])
{
	u32 i, rf_reg_8f[DPK_RF_PATH_NUM_8195B] = {0x0};

	for (i = 0; i < DPK_RF_REG_NUM_8195B; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_A]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_B 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_B]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_C 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_C]);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_D 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_D]);
#endif
	}
	/*reload RF 0x8f for non-saving power mode*/
	for (i = 0; i < DPK_RF_PATH_NUM_8195B; i++) {
		rf_reg_8f[i] = odm_get_rf_reg(dm, RF_PATH_A, RF_0x8f,
					      0x00fff);
		odm_set_rf_reg(dm, RF_PATH_A,
			       RF_0x8f, RFREG_MASK, (0xa8000 | rf_reg_8f[i]));
	}
}

void _dpk_mode_8195b(struct dm_struct *dm, boolean is_dpkmode)
{
	u32 temp1, temp2;
	/*RF & page 1b can't be write in iqk mode*/
	if (is_dpkmode)
		odm_set_bb_reg(dm, 0x1c38, BIT(31), 0x1);
	else
		odm_set_bb_reg(dm, 0x1c38, BIT(31), 0x0);
}

void _dpk_clear_even_odd_8195b(struct dm_struct *dm)
{
	u8 i;
	u32 reg_1bdc;

	/*clear even*/
	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xd0000000 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}
	/*clear odd*/
	for (i = 1; i < 0x80; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x90000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		/*RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bdc = 0x%x\n", reg_1bdc);*/
	}

	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
}

void _dpk_init_phy_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 path;

	//odm_set_bb_reg(dm, 0x1c38, BIT(31), 0x0);
	//odm_set_bb_reg(dm, 0x1c44, BIT(17) | BIT(16), 0x3);
	//odm_set_bb_reg(dm, 0x1904, BIT(17), 0x1);

	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		odm_write_4byte(dm, 0x1C44, 0xA34300F3);
		odm_write_4byte(dm, 0x1b00, 0x00000008);
		odm_write_4byte(dm, 0x1b00, 0x00A70008);
		odm_write_4byte(dm, 0x1b00, 0x00150008);
		odm_write_4byte(dm, 0x1b00, 0x00000008);
		odm_write_4byte(dm, 0x1b04, 0xE24629D2);
		odm_write_4byte(dm, 0x1b08, 0x00000080);
		odm_write_4byte(dm, 0x1b0c, 0x00000000);
		odm_write_4byte(dm, 0x1b10, 0x00010C00);
		odm_write_4byte(dm, 0x1b14, 0x00000000);
		odm_write_4byte(dm, 0x1b18, 0x00292903);
		//odm_write_4byte(dm, 0x1b1c, 0xA21FFC32);
		odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
		odm_write_4byte(dm, 0x1b20, 0x03040008);
		odm_write_4byte(dm, 0x1b24, 0x00060008);
		odm_write_4byte(dm, 0x1b28, 0x80060300);
		odm_write_4byte(dm, 0x1b2C, 0x00180018);
		odm_write_4byte(dm, 0x1b30, 0x20000000);
		odm_write_4byte(dm, 0x1b34, 0x00000800);
		odm_write_4byte(dm, 0x1b38, 0x20000000);
		odm_write_4byte(dm, 0x1b3C, 0x20000000);
		odm_write_4byte(dm, 0x1bc0, 0x01000000);
		odm_write_4byte(dm, 0x1b90, 0x0105f038);
		odm_write_4byte(dm, 0x1b94, 0xf76d9f84);
		//odm_write_4byte(dm, 0x1bc8, 0x000c44aa);
		odm_write_4byte(dm, 0x1bc8, 0x000c66aa);
		odm_write_4byte(dm, 0x1bcc, 0x11160200);
		odm_write_4byte(dm, 0x1bb8, 0x000fffff);
		odm_write_4byte(dm, 0x1bbc, 0x00009DBF);
		odm_write_4byte(dm, 0x1b98, 0x41382e21);
		odm_write_4byte(dm, 0x1b9c, 0x5b554f48);
		odm_write_4byte(dm, 0x1ba0, 0x6f6b6661);
		odm_write_4byte(dm, 0x1ba4, 0x817d7874);
		odm_write_4byte(dm, 0x1ba8, 0x908c8884);
		odm_write_4byte(dm, 0x1bac, 0x9d9a9793);
		odm_write_4byte(dm, 0x1bb0, 0xaaa7a4a1);
		odm_write_4byte(dm, 0x1bb4, 0xb6b3b0ad);
		odm_write_4byte(dm, 0x1b40, 0x02ce03e9);
		odm_write_4byte(dm, 0x1b44, 0x01fd0249);
		odm_write_4byte(dm, 0x1b48, 0x01a101c9);
		odm_write_4byte(dm, 0x1b4c, 0x016a0181);
		odm_write_4byte(dm, 0x1b50, 0x01430155);
		odm_write_4byte(dm, 0x1b54, 0x01270135);
		odm_write_4byte(dm, 0x1b58, 0x0112011c);
		odm_write_4byte(dm, 0x1b5c, 0x01000108);
		odm_write_4byte(dm, 0x1b60, 0x00f100f8);
		odm_write_4byte(dm, 0x1b64, 0x00e500eb);
		odm_write_4byte(dm, 0x1b68, 0x00db00e0);
		odm_write_4byte(dm, 0x1b6c, 0x00d100d5);
		odm_write_4byte(dm, 0x1b70, 0x00c900cd);
		odm_write_4byte(dm, 0x1b74, 0x00c200c5);
		odm_write_4byte(dm, 0x1b78, 0x00bb00be);
		odm_write_4byte(dm, 0x1b7c, 0x00b500b8);
		odm_write_4byte(dm, 0x1bdc, 0x40caffe1);
		odm_write_4byte(dm, 0x1bdc, 0x4080a1e3);
		odm_write_4byte(dm, 0x1bdc, 0x405165e5);
		odm_write_4byte(dm, 0x1bdc, 0x403340e7);
		odm_write_4byte(dm, 0x1bdc, 0x402028e9);
		odm_write_4byte(dm, 0x1bdc, 0x401419eb);
		odm_write_4byte(dm, 0x1bdc, 0x400d10ed);
		odm_write_4byte(dm, 0x1bdc, 0x40080aef);
		odm_write_4byte(dm, 0x1bdc, 0x400506f1);
		odm_write_4byte(dm, 0x1bdc, 0x400304f3);
		odm_write_4byte(dm, 0x1bdc, 0x400203f5);
		odm_write_4byte(dm, 0x1bdc, 0x400102f7);
		odm_write_4byte(dm, 0x1bdc, 0x400101f9);
		odm_write_4byte(dm, 0x1bdc, 0x400101fb);
		odm_write_4byte(dm, 0x1bdc, 0x400101fd);
		odm_write_4byte(dm, 0x1bdc, 0x400101ff);
		odm_write_4byte(dm, 0x1bdc, 0x40caff81);
		odm_write_4byte(dm, 0x1bdc, 0x4080a183);
		odm_write_4byte(dm, 0x1bdc, 0x40516585);
		odm_write_4byte(dm, 0x1bdc, 0x40334087);
		odm_write_4byte(dm, 0x1bdc, 0x40202889);
		odm_write_4byte(dm, 0x1bdc, 0x4014198b);
		odm_write_4byte(dm, 0x1bdc, 0x400d108d);
		odm_write_4byte(dm, 0x1bdc, 0x40080a8f);
		odm_write_4byte(dm, 0x1bdc, 0x40050691);
		odm_write_4byte(dm, 0x1bdc, 0x40030493);
		odm_write_4byte(dm, 0x1bdc, 0x40020395);
		odm_write_4byte(dm, 0x1bdc, 0x40010297);
		odm_write_4byte(dm, 0x1bdc, 0x40010199);
		odm_write_4byte(dm, 0x1bdc, 0x4001019b);
		odm_write_4byte(dm, 0x1bdc, 0x4001019d);
		odm_write_4byte(dm, 0x1bdc, 0x4001019f);
		odm_write_4byte(dm, 0x1bdc, 0x00000000);
		_dpk_clear_even_odd_8195b(dm);
	}
}

void _dpk_nctl_8195b(struct dm_struct *dm)
{
	odm_write_4byte(dm, 0x1b00, 0x00000000);
	odm_write_4byte(dm, 0x1b80, 0x00000007);
	odm_write_4byte(dm, 0x1b80, 0x090a0005);
	odm_write_4byte(dm, 0x1b80, 0x090a0007);
	odm_write_4byte(dm, 0x1b80, 0x0ffe0015);
	odm_write_4byte(dm, 0x1b80, 0x0ffe0017);
	odm_write_4byte(dm, 0x1b80, 0x00220025);
	odm_write_4byte(dm, 0x1b80, 0x00220027);
	odm_write_4byte(dm, 0x1b80, 0x00040035);
	odm_write_4byte(dm, 0x1b80, 0x00040037);
	odm_write_4byte(dm, 0x1b80, 0x05c00045);
	odm_write_4byte(dm, 0x1b80, 0x05c00047);
	odm_write_4byte(dm, 0x1b80, 0x00070055);
	odm_write_4byte(dm, 0x1b80, 0x00070057);
	odm_write_4byte(dm, 0x1b80, 0x64000065);
	odm_write_4byte(dm, 0x1b80, 0x64000067);
	odm_write_4byte(dm, 0x1b80, 0x00020075);
	odm_write_4byte(dm, 0x1b80, 0x00020077);
	odm_write_4byte(dm, 0x1b80, 0x00080085);
	odm_write_4byte(dm, 0x1b80, 0x00080087);
	odm_write_4byte(dm, 0x1b80, 0x80000095);
	odm_write_4byte(dm, 0x1b80, 0x80000097);
	odm_write_4byte(dm, 0x1b80, 0x090800a5);
	odm_write_4byte(dm, 0x1b80, 0x090800a7);
	odm_write_4byte(dm, 0x1b80, 0x0f0200b5);
	odm_write_4byte(dm, 0x1b80, 0x0f0200b7);
	odm_write_4byte(dm, 0x1b80, 0x002200c5);
	odm_write_4byte(dm, 0x1b80, 0x002200c7);
	odm_write_4byte(dm, 0x1b80, 0x000400d5);
	odm_write_4byte(dm, 0x1b80, 0x000400d7);
	odm_write_4byte(dm, 0x1b80, 0x05c000e5);
	odm_write_4byte(dm, 0x1b80, 0x05c000e7);
	odm_write_4byte(dm, 0x1b80, 0x000700f5);
	odm_write_4byte(dm, 0x1b80, 0x000700f7);
	odm_write_4byte(dm, 0x1b80, 0x64020105);
	odm_write_4byte(dm, 0x1b80, 0x64020107);
	odm_write_4byte(dm, 0x1b80, 0x00020115);
	odm_write_4byte(dm, 0x1b80, 0x00020117);
	odm_write_4byte(dm, 0x1b80, 0x00040125);
	odm_write_4byte(dm, 0x1b80, 0x00040127);
	odm_write_4byte(dm, 0x1b80, 0x4a000135);
	odm_write_4byte(dm, 0x1b80, 0x4a000137);
	odm_write_4byte(dm, 0x1b80, 0x4b040145);
	odm_write_4byte(dm, 0x1b80, 0x4b040147);
	odm_write_4byte(dm, 0x1b80, 0x86030155);
	odm_write_4byte(dm, 0x1b80, 0x86030157);
	odm_write_4byte(dm, 0x1b80, 0x40090165);
	odm_write_4byte(dm, 0x1b80, 0x40090167);
	odm_write_4byte(dm, 0x1b80, 0xe0220175);
	odm_write_4byte(dm, 0x1b80, 0xe0220177);
	odm_write_4byte(dm, 0x1b80, 0x4b050185);
	odm_write_4byte(dm, 0x1b80, 0x4b050187);
	odm_write_4byte(dm, 0x1b80, 0x87030195);
	odm_write_4byte(dm, 0x1b80, 0x87030197);
	odm_write_4byte(dm, 0x1b80, 0x400b01a5);
	odm_write_4byte(dm, 0x1b80, 0x400b01a7);
	odm_write_4byte(dm, 0x1b80, 0xe02201b5);
	odm_write_4byte(dm, 0x1b80, 0xe02201b7);
	odm_write_4byte(dm, 0x1b80, 0x4b0001c5);
	odm_write_4byte(dm, 0x1b80, 0x4b0001c7);
	odm_write_4byte(dm, 0x1b80, 0x000701d5);
	odm_write_4byte(dm, 0x1b80, 0x000701d7);
	odm_write_4byte(dm, 0x1b80, 0x4c0001e5);
	odm_write_4byte(dm, 0x1b80, 0x4c0001e7);
	odm_write_4byte(dm, 0x1b80, 0x000401f5);
	odm_write_4byte(dm, 0x1b80, 0x000401f7);
	odm_write_4byte(dm, 0x1b80, 0x50550205);
	odm_write_4byte(dm, 0x1b80, 0x50550207);
	odm_write_4byte(dm, 0x1b80, 0x30000215);
	odm_write_4byte(dm, 0x1b80, 0x30000217);
	odm_write_4byte(dm, 0x1b80, 0xe1bd0225);
	odm_write_4byte(dm, 0x1b80, 0xe1bd0227);
	odm_write_4byte(dm, 0x1b80, 0xa50d0235);
	odm_write_4byte(dm, 0x1b80, 0xa50d0237);
	odm_write_4byte(dm, 0x1b80, 0xf0110245);
	odm_write_4byte(dm, 0x1b80, 0xf0110247);
	odm_write_4byte(dm, 0x1b80, 0xf1110255);
	odm_write_4byte(dm, 0x1b80, 0xf1110257);
	odm_write_4byte(dm, 0x1b80, 0xf2110265);
	odm_write_4byte(dm, 0x1b80, 0xf2110267);
	odm_write_4byte(dm, 0x1b80, 0xf3110275);
	odm_write_4byte(dm, 0x1b80, 0xf3110277);
	odm_write_4byte(dm, 0x1b80, 0xf4110285);
	odm_write_4byte(dm, 0x1b80, 0xf4110287);
	odm_write_4byte(dm, 0x1b80, 0xf5110295);
	odm_write_4byte(dm, 0x1b80, 0xf5110297);
	odm_write_4byte(dm, 0x1b80, 0xf61102a5);
	odm_write_4byte(dm, 0x1b80, 0xf61102a7);
	odm_write_4byte(dm, 0x1b80, 0xf71102b5);
	odm_write_4byte(dm, 0x1b80, 0xf71102b7);
	odm_write_4byte(dm, 0x1b80, 0xf81102c5);
	odm_write_4byte(dm, 0x1b80, 0xf81102c7);
	odm_write_4byte(dm, 0x1b80, 0xf91102d5);
	odm_write_4byte(dm, 0x1b80, 0xf91102d7);
	odm_write_4byte(dm, 0x1b80, 0xfa1102e5);
	odm_write_4byte(dm, 0x1b80, 0xfa1102e7);
	odm_write_4byte(dm, 0x1b80, 0xfb1102f5);
	odm_write_4byte(dm, 0x1b80, 0xfb1102f7);
	odm_write_4byte(dm, 0x1b80, 0xf0110305);
	odm_write_4byte(dm, 0x1b80, 0xf0110307);
	odm_write_4byte(dm, 0x1b80, 0xf1110315);
	odm_write_4byte(dm, 0x1b80, 0xf1110317);
	odm_write_4byte(dm, 0x1b80, 0xf2110325);
	odm_write_4byte(dm, 0x1b80, 0xf2110327);
	odm_write_4byte(dm, 0x1b80, 0xf3110335);
	odm_write_4byte(dm, 0x1b80, 0xf3110337);
	odm_write_4byte(dm, 0x1b80, 0x00010345);
	odm_write_4byte(dm, 0x1b80, 0x00010347);
	odm_write_4byte(dm, 0x1b80, 0x30460355);
	odm_write_4byte(dm, 0x1b80, 0x30460357);
	odm_write_4byte(dm, 0x1b80, 0x305e0365);
	odm_write_4byte(dm, 0x1b80, 0x305e0367);
	odm_write_4byte(dm, 0x1b80, 0x30ad0375);
	odm_write_4byte(dm, 0x1b80, 0x30ad0377);
	odm_write_4byte(dm, 0x1b80, 0x30b00385);
	odm_write_4byte(dm, 0x1b80, 0x30b00387);
	odm_write_4byte(dm, 0x1b80, 0x30600395);
	odm_write_4byte(dm, 0x1b80, 0x30600397);
	odm_write_4byte(dm, 0x1b80, 0x306b03a5);
	odm_write_4byte(dm, 0x1b80, 0x306b03a7);
	odm_write_4byte(dm, 0x1b80, 0x307603b5);
	odm_write_4byte(dm, 0x1b80, 0x307603b7);
	odm_write_4byte(dm, 0x1b80, 0x30bb03c5);
	odm_write_4byte(dm, 0x1b80, 0x30bb03c7);
	odm_write_4byte(dm, 0x1b80, 0x30b403d5);
	odm_write_4byte(dm, 0x1b80, 0x30b403d7);
	odm_write_4byte(dm, 0x1b80, 0x30cb03e5);
	odm_write_4byte(dm, 0x1b80, 0x30cb03e7);
	odm_write_4byte(dm, 0x1b80, 0x30d603f5);
	odm_write_4byte(dm, 0x1b80, 0x30d603f7);
	odm_write_4byte(dm, 0x1b80, 0x30e10405);
	odm_write_4byte(dm, 0x1b80, 0x30e10407);
	odm_write_4byte(dm, 0x1b80, 0x30450415);
	odm_write_4byte(dm, 0x1b80, 0x30450417);
	odm_write_4byte(dm, 0x1b80, 0x31140425);
	odm_write_4byte(dm, 0x1b80, 0x31140427);
	odm_write_4byte(dm, 0x1b80, 0x31250435);
	odm_write_4byte(dm, 0x1b80, 0x31250437);
	odm_write_4byte(dm, 0x1b80, 0x31390445);
	odm_write_4byte(dm, 0x1b80, 0x31390447);
	odm_write_4byte(dm, 0x1b80, 0x62060455);
	odm_write_4byte(dm, 0x1b80, 0x62060457);
	odm_write_4byte(dm, 0x1b80, 0xe1580465);
	odm_write_4byte(dm, 0x1b80, 0xe1580467);
	odm_write_4byte(dm, 0x1b80, 0x4d040475);
	odm_write_4byte(dm, 0x1b80, 0x4d040477);
	odm_write_4byte(dm, 0x1b80, 0x20800485);
	odm_write_4byte(dm, 0x1b80, 0x20800487);
	odm_write_4byte(dm, 0x1b80, 0x00000495);
	odm_write_4byte(dm, 0x1b80, 0x00000497);
	odm_write_4byte(dm, 0x1b80, 0x4d0004a5);
	odm_write_4byte(dm, 0x1b80, 0x4d0004a7);
	odm_write_4byte(dm, 0x1b80, 0x550704b5);
	odm_write_4byte(dm, 0x1b80, 0x550704b7);
	odm_write_4byte(dm, 0x1b80, 0xe15004c5);
	odm_write_4byte(dm, 0x1b80, 0xe15004c7);
	odm_write_4byte(dm, 0x1b80, 0xe15004d5);
	odm_write_4byte(dm, 0x1b80, 0xe15004d7);
	odm_write_4byte(dm, 0x1b80, 0x4d0404e5);
	odm_write_4byte(dm, 0x1b80, 0x4d0404e7);
	odm_write_4byte(dm, 0x1b80, 0x208804f5);
	odm_write_4byte(dm, 0x1b80, 0x208804f7);
	odm_write_4byte(dm, 0x1b80, 0x02000505);
	odm_write_4byte(dm, 0x1b80, 0x02000507);
	odm_write_4byte(dm, 0x1b80, 0x4d000515);
	odm_write_4byte(dm, 0x1b80, 0x4d000517);
	odm_write_4byte(dm, 0x1b80, 0x550f0525);
	odm_write_4byte(dm, 0x1b80, 0x550f0527);
	odm_write_4byte(dm, 0x1b80, 0xe1500535);
	odm_write_4byte(dm, 0x1b80, 0xe1500537);
	odm_write_4byte(dm, 0x1b80, 0x4f020545);
	odm_write_4byte(dm, 0x1b80, 0x4f020547);
	odm_write_4byte(dm, 0x1b80, 0x4e000555);
	odm_write_4byte(dm, 0x1b80, 0x4e000557);
	odm_write_4byte(dm, 0x1b80, 0x53020565);
	odm_write_4byte(dm, 0x1b80, 0x53020567);
	odm_write_4byte(dm, 0x1b80, 0x52010575);
	odm_write_4byte(dm, 0x1b80, 0x52010577);
	odm_write_4byte(dm, 0x1b80, 0xe1540585);
	odm_write_4byte(dm, 0x1b80, 0xe1540587);
	odm_write_4byte(dm, 0x1b80, 0x4d080595);
	odm_write_4byte(dm, 0x1b80, 0x4d080597);
	odm_write_4byte(dm, 0x1b80, 0x571005a5);
	odm_write_4byte(dm, 0x1b80, 0x571005a7);
	odm_write_4byte(dm, 0x1b80, 0x570005b5);
	odm_write_4byte(dm, 0x1b80, 0x570005b7);
	odm_write_4byte(dm, 0x1b80, 0x4d0005c5);
	odm_write_4byte(dm, 0x1b80, 0x4d0005c7);
	odm_write_4byte(dm, 0x1b80, 0x000105d5);
	odm_write_4byte(dm, 0x1b80, 0x000105d7);
	odm_write_4byte(dm, 0x1b80, 0xe15805e5);
	odm_write_4byte(dm, 0x1b80, 0xe15805e7);
	odm_write_4byte(dm, 0x1b80, 0x000105f5);
	odm_write_4byte(dm, 0x1b80, 0x000105f7);
	odm_write_4byte(dm, 0x1b80, 0x30820605);
	odm_write_4byte(dm, 0x1b80, 0x30820607);
	odm_write_4byte(dm, 0x1b80, 0x00230615);
	odm_write_4byte(dm, 0x1b80, 0x00230617);
	odm_write_4byte(dm, 0x1b80, 0xe1b00625);
	odm_write_4byte(dm, 0x1b80, 0xe1b00627);
	odm_write_4byte(dm, 0x1b80, 0x00020635);
	odm_write_4byte(dm, 0x1b80, 0x00020637);
	odm_write_4byte(dm, 0x1b80, 0x54e90645);
	odm_write_4byte(dm, 0x1b80, 0x54e90647);
	odm_write_4byte(dm, 0x1b80, 0x0ba60655);
	odm_write_4byte(dm, 0x1b80, 0x0ba60657);
	odm_write_4byte(dm, 0x1b80, 0x00230665);
	odm_write_4byte(dm, 0x1b80, 0x00230667);
	odm_write_4byte(dm, 0x1b80, 0xe1b00675);
	odm_write_4byte(dm, 0x1b80, 0xe1b00677);
	odm_write_4byte(dm, 0x1b80, 0x00020685);
	odm_write_4byte(dm, 0x1b80, 0x00020687);
	odm_write_4byte(dm, 0x1b80, 0x4d300695);
	odm_write_4byte(dm, 0x1b80, 0x4d300697);
	odm_write_4byte(dm, 0x1b80, 0x309d06a5);
	odm_write_4byte(dm, 0x1b80, 0x309d06a7);
	odm_write_4byte(dm, 0x1b80, 0x307d06b5);
	odm_write_4byte(dm, 0x1b80, 0x307d06b7);
	odm_write_4byte(dm, 0x1b80, 0x002206c5);
	odm_write_4byte(dm, 0x1b80, 0x002206c7);
	odm_write_4byte(dm, 0x1b80, 0xe1b006d5);
	odm_write_4byte(dm, 0x1b80, 0xe1b006d7);
	odm_write_4byte(dm, 0x1b80, 0x000206e5);
	odm_write_4byte(dm, 0x1b80, 0x000206e7);
	odm_write_4byte(dm, 0x1b80, 0x54e806f5);
	odm_write_4byte(dm, 0x1b80, 0x54e806f7);
	odm_write_4byte(dm, 0x1b80, 0x0ba60705);
	odm_write_4byte(dm, 0x1b80, 0x0ba60707);
	odm_write_4byte(dm, 0x1b80, 0x00220715);
	odm_write_4byte(dm, 0x1b80, 0x00220717);
	odm_write_4byte(dm, 0x1b80, 0xe1b00725);
	odm_write_4byte(dm, 0x1b80, 0xe1b00727);
	odm_write_4byte(dm, 0x1b80, 0x00020735);
	odm_write_4byte(dm, 0x1b80, 0x00020737);
	odm_write_4byte(dm, 0x1b80, 0x4d300745);
	odm_write_4byte(dm, 0x1b80, 0x4d300747);
	odm_write_4byte(dm, 0x1b80, 0x309d0755);
	odm_write_4byte(dm, 0x1b80, 0x309d0757);
	odm_write_4byte(dm, 0x1b80, 0x6c180765);
	odm_write_4byte(dm, 0x1b80, 0x6c180767);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0775);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0777);
	odm_write_4byte(dm, 0x1b80, 0xe1580785);
	odm_write_4byte(dm, 0x1b80, 0xe1580787);
	odm_write_4byte(dm, 0x1b80, 0xe1b00795);
	odm_write_4byte(dm, 0x1b80, 0xe1b00797);
	odm_write_4byte(dm, 0x1b80, 0x6c4807a5);
	odm_write_4byte(dm, 0x1b80, 0x6c4807a7);
	odm_write_4byte(dm, 0x1b80, 0xe15807b5);
	odm_write_4byte(dm, 0x1b80, 0xe15807b7);
	odm_write_4byte(dm, 0x1b80, 0xe1b007c5);
	odm_write_4byte(dm, 0x1b80, 0xe1b007c7);
	odm_write_4byte(dm, 0x1b80, 0x0ba807d5);
	odm_write_4byte(dm, 0x1b80, 0x0ba807d7);
	odm_write_4byte(dm, 0x1b80, 0x6c8807e5);
	odm_write_4byte(dm, 0x1b80, 0x6c8807e7);
	odm_write_4byte(dm, 0x1b80, 0x6d0f07f5);
	odm_write_4byte(dm, 0x1b80, 0x6d0f07f7);
	odm_write_4byte(dm, 0x1b80, 0xe1580805);
	odm_write_4byte(dm, 0x1b80, 0xe1580807);
	odm_write_4byte(dm, 0x1b80, 0xe1b00815);
	odm_write_4byte(dm, 0x1b80, 0xe1b00817);
	odm_write_4byte(dm, 0x1b80, 0x0ba90825);
	odm_write_4byte(dm, 0x1b80, 0x0ba90827);
	odm_write_4byte(dm, 0x1b80, 0x6cc80835);
	odm_write_4byte(dm, 0x1b80, 0x6cc80837);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0845);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0847);
	odm_write_4byte(dm, 0x1b80, 0xe1580855);
	odm_write_4byte(dm, 0x1b80, 0xe1580857);
	odm_write_4byte(dm, 0x1b80, 0xe1b00865);
	odm_write_4byte(dm, 0x1b80, 0xe1b00867);
	odm_write_4byte(dm, 0x1b80, 0x6cf80875);
	odm_write_4byte(dm, 0x1b80, 0x6cf80877);
	odm_write_4byte(dm, 0x1b80, 0xe1580885);
	odm_write_4byte(dm, 0x1b80, 0xe1580887);
	odm_write_4byte(dm, 0x1b80, 0xe1b00895);
	odm_write_4byte(dm, 0x1b80, 0xe1b00897);
	odm_write_4byte(dm, 0x1b80, 0x6c0808a5);
	odm_write_4byte(dm, 0x1b80, 0x6c0808a7);
	odm_write_4byte(dm, 0x1b80, 0x6d0008b5);
	odm_write_4byte(dm, 0x1b80, 0x6d0008b7);
	odm_write_4byte(dm, 0x1b80, 0xe15808c5);
	odm_write_4byte(dm, 0x1b80, 0xe15808c7);
	odm_write_4byte(dm, 0x1b80, 0xe1b008d5);
	odm_write_4byte(dm, 0x1b80, 0xe1b008d7);
	odm_write_4byte(dm, 0x1b80, 0x6c3808e5);
	odm_write_4byte(dm, 0x1b80, 0x6c3808e7);
	odm_write_4byte(dm, 0x1b80, 0xe15808f5);
	odm_write_4byte(dm, 0x1b80, 0xe15808f7);
	odm_write_4byte(dm, 0x1b80, 0xe1b00905);
	odm_write_4byte(dm, 0x1b80, 0xe1b00907);
	odm_write_4byte(dm, 0x1b80, 0xf4d00915);
	odm_write_4byte(dm, 0x1b80, 0xf4d00917);
	odm_write_4byte(dm, 0x1b80, 0x6c780925);
	odm_write_4byte(dm, 0x1b80, 0x6c780927);
	odm_write_4byte(dm, 0x1b80, 0xe1580935);
	odm_write_4byte(dm, 0x1b80, 0xe1580937);
	odm_write_4byte(dm, 0x1b80, 0xe1b00945);
	odm_write_4byte(dm, 0x1b80, 0xe1b00947);
	odm_write_4byte(dm, 0x1b80, 0xf5d70955);
	odm_write_4byte(dm, 0x1b80, 0xf5d70957);
	odm_write_4byte(dm, 0x1b80, 0x6cb80965);
	odm_write_4byte(dm, 0x1b80, 0x6cb80967);
	odm_write_4byte(dm, 0x1b80, 0xe1580975);
	odm_write_4byte(dm, 0x1b80, 0xe1580977);
	odm_write_4byte(dm, 0x1b80, 0xe1b00985);
	odm_write_4byte(dm, 0x1b80, 0xe1b00987);
	odm_write_4byte(dm, 0x1b80, 0x6ce80995);
	odm_write_4byte(dm, 0x1b80, 0x6ce80997);
	odm_write_4byte(dm, 0x1b80, 0xe15809a5);
	odm_write_4byte(dm, 0x1b80, 0xe15809a7);
	odm_write_4byte(dm, 0x1b80, 0xe1b009b5);
	odm_write_4byte(dm, 0x1b80, 0xe1b009b7);
	odm_write_4byte(dm, 0x1b80, 0x4d3009c5);
	odm_write_4byte(dm, 0x1b80, 0x4d3009c7);
	odm_write_4byte(dm, 0x1b80, 0x550109d5);
	odm_write_4byte(dm, 0x1b80, 0x550109d7);
	odm_write_4byte(dm, 0x1b80, 0x570409e5);
	odm_write_4byte(dm, 0x1b80, 0x570409e7);
	odm_write_4byte(dm, 0x1b80, 0x570009f5);
	odm_write_4byte(dm, 0x1b80, 0x570009f7);
	odm_write_4byte(dm, 0x1b80, 0x96000a05);
	odm_write_4byte(dm, 0x1b80, 0x96000a07);
	odm_write_4byte(dm, 0x1b80, 0x57080a15);
	odm_write_4byte(dm, 0x1b80, 0x57080a17);
	odm_write_4byte(dm, 0x1b80, 0x57000a25);
	odm_write_4byte(dm, 0x1b80, 0x57000a27);
	odm_write_4byte(dm, 0x1b80, 0x95000a35);
	odm_write_4byte(dm, 0x1b80, 0x95000a37);
	odm_write_4byte(dm, 0x1b80, 0x4d000a45);
	odm_write_4byte(dm, 0x1b80, 0x4d000a47);
	odm_write_4byte(dm, 0x1b80, 0x63070a55);
	odm_write_4byte(dm, 0x1b80, 0x63070a57);
	odm_write_4byte(dm, 0x1b80, 0x7b200a65);
	odm_write_4byte(dm, 0x1b80, 0x7b200a67);
	odm_write_4byte(dm, 0x1b80, 0x7a000a75);
	odm_write_4byte(dm, 0x1b80, 0x7a000a77);
	odm_write_4byte(dm, 0x1b80, 0x79000a85);
	odm_write_4byte(dm, 0x1b80, 0x79000a87);
	odm_write_4byte(dm, 0x1b80, 0x7f200a95);
	odm_write_4byte(dm, 0x1b80, 0x7f200a97);
	odm_write_4byte(dm, 0x1b80, 0x7e000aa5);
	odm_write_4byte(dm, 0x1b80, 0x7e000aa7);
	odm_write_4byte(dm, 0x1b80, 0x7d000ab5);
	odm_write_4byte(dm, 0x1b80, 0x7d000ab7);
	odm_write_4byte(dm, 0x1b80, 0x00010ac5);
	odm_write_4byte(dm, 0x1b80, 0x00010ac7);
	odm_write_4byte(dm, 0x1b80, 0x62060ad5);
	odm_write_4byte(dm, 0x1b80, 0x62060ad7);
	odm_write_4byte(dm, 0x1b80, 0xe1580ae5);
	odm_write_4byte(dm, 0x1b80, 0xe1580ae7);
	odm_write_4byte(dm, 0x1b80, 0x00010af5);
	odm_write_4byte(dm, 0x1b80, 0x00010af7);
	odm_write_4byte(dm, 0x1b80, 0x5c320b05);
	odm_write_4byte(dm, 0x1b80, 0x5c320b07);
	odm_write_4byte(dm, 0x1b80, 0xe1ac0b15);
	odm_write_4byte(dm, 0x1b80, 0xe1ac0b17);
	odm_write_4byte(dm, 0x1b80, 0xe1860b25);
	odm_write_4byte(dm, 0x1b80, 0xe1860b27);
	odm_write_4byte(dm, 0x1b80, 0x00010b35);
	odm_write_4byte(dm, 0x1b80, 0x00010b37);
	odm_write_4byte(dm, 0x1b80, 0x5c320b45);
	odm_write_4byte(dm, 0x1b80, 0x5c320b47);
	odm_write_4byte(dm, 0x1b80, 0x6c480b55);
	odm_write_4byte(dm, 0x1b80, 0x6c480b57);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0b65);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0b67);
	odm_write_4byte(dm, 0x1b80, 0x62060b75);
	odm_write_4byte(dm, 0x1b80, 0x62060b77);
	odm_write_4byte(dm, 0x1b80, 0x0bb00b85);
	odm_write_4byte(dm, 0x1b80, 0x0bb00b87);
	odm_write_4byte(dm, 0x1b80, 0xe1580b95);
	odm_write_4byte(dm, 0x1b80, 0xe1580b97);
	odm_write_4byte(dm, 0x1b80, 0xe1b00ba5);
	odm_write_4byte(dm, 0x1b80, 0xe1b00ba7);
	odm_write_4byte(dm, 0x1b80, 0x5c320bb5);
	odm_write_4byte(dm, 0x1b80, 0x5c320bb7);
	odm_write_4byte(dm, 0x1b80, 0x6cc80bc5);
	odm_write_4byte(dm, 0x1b80, 0x6cc80bc7);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0bd5);
	odm_write_4byte(dm, 0x1b80, 0x6d0f0bd7);
	odm_write_4byte(dm, 0x1b80, 0x62060be5);
	odm_write_4byte(dm, 0x1b80, 0x62060be7);
	odm_write_4byte(dm, 0x1b80, 0x0bb10bf5);
	odm_write_4byte(dm, 0x1b80, 0x0bb10bf7);
	odm_write_4byte(dm, 0x1b80, 0xe1580c05);
	odm_write_4byte(dm, 0x1b80, 0xe1580c07);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c15);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c17);
	odm_write_4byte(dm, 0x1b80, 0x6c380c25);
	odm_write_4byte(dm, 0x1b80, 0x6c380c27);
	odm_write_4byte(dm, 0x1b80, 0x6d000c35);
	odm_write_4byte(dm, 0x1b80, 0x6d000c37);
	odm_write_4byte(dm, 0x1b80, 0xe1580c45);
	odm_write_4byte(dm, 0x1b80, 0xe1580c47);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c55);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c57);
	odm_write_4byte(dm, 0x1b80, 0xf7040c65);
	odm_write_4byte(dm, 0x1b80, 0xf7040c67);
	odm_write_4byte(dm, 0x1b80, 0x6cb80c75);
	odm_write_4byte(dm, 0x1b80, 0x6cb80c77);
	odm_write_4byte(dm, 0x1b80, 0xe1580c85);
	odm_write_4byte(dm, 0x1b80, 0xe1580c87);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c95);
	odm_write_4byte(dm, 0x1b80, 0xe1b00c97);
	odm_write_4byte(dm, 0x1b80, 0x00010ca5);
	odm_write_4byte(dm, 0x1b80, 0x00010ca7);
	odm_write_4byte(dm, 0x1b80, 0x30f10cb5);
	odm_write_4byte(dm, 0x1b80, 0x30f10cb7);
	odm_write_4byte(dm, 0x1b80, 0x00230cc5);
	odm_write_4byte(dm, 0x1b80, 0x00230cc7);
	odm_write_4byte(dm, 0x1b80, 0xe1b50cd5);
	odm_write_4byte(dm, 0x1b80, 0xe1b50cd7);
	odm_write_4byte(dm, 0x1b80, 0x00020ce5);
	odm_write_4byte(dm, 0x1b80, 0x00020ce7);
	odm_write_4byte(dm, 0x1b80, 0x54e90cf5);
	odm_write_4byte(dm, 0x1b80, 0x54e90cf7);
	odm_write_4byte(dm, 0x1b80, 0x0ba60d05);
	odm_write_4byte(dm, 0x1b80, 0x0ba60d07);
	odm_write_4byte(dm, 0x1b80, 0x00230d15);
	odm_write_4byte(dm, 0x1b80, 0x00230d17);
	odm_write_4byte(dm, 0x1b80, 0xe1b50d25);
	odm_write_4byte(dm, 0x1b80, 0xe1b50d27);
	odm_write_4byte(dm, 0x1b80, 0x00020d35);
	odm_write_4byte(dm, 0x1b80, 0x00020d37);
	odm_write_4byte(dm, 0x1b80, 0x4d100d45);
	odm_write_4byte(dm, 0x1b80, 0x4d100d47);
	odm_write_4byte(dm, 0x1b80, 0x309d0d55);
	odm_write_4byte(dm, 0x1b80, 0x309d0d57);
	odm_write_4byte(dm, 0x1b80, 0x30ea0d65);
	odm_write_4byte(dm, 0x1b80, 0x30ea0d67);
	odm_write_4byte(dm, 0x1b80, 0x00220d75);
	odm_write_4byte(dm, 0x1b80, 0x00220d77);
	odm_write_4byte(dm, 0x1b80, 0xe1b50d85);
	odm_write_4byte(dm, 0x1b80, 0xe1b50d87);
	odm_write_4byte(dm, 0x1b80, 0x00020d95);
	odm_write_4byte(dm, 0x1b80, 0x00020d97);
	odm_write_4byte(dm, 0x1b80, 0x54e80da5);
	odm_write_4byte(dm, 0x1b80, 0x54e80da7);
	odm_write_4byte(dm, 0x1b80, 0x0ba60db5);
	odm_write_4byte(dm, 0x1b80, 0x0ba60db7);
	odm_write_4byte(dm, 0x1b80, 0x00220dc5);
	odm_write_4byte(dm, 0x1b80, 0x00220dc7);
	odm_write_4byte(dm, 0x1b80, 0xe1b50dd5);
	odm_write_4byte(dm, 0x1b80, 0xe1b50dd7);
	odm_write_4byte(dm, 0x1b80, 0x00020de5);
	odm_write_4byte(dm, 0x1b80, 0x00020de7);
	odm_write_4byte(dm, 0x1b80, 0x4d100df5);
	odm_write_4byte(dm, 0x1b80, 0x4d100df7);
	odm_write_4byte(dm, 0x1b80, 0x309d0e05);
	odm_write_4byte(dm, 0x1b80, 0x309d0e07);
	odm_write_4byte(dm, 0x1b80, 0x5c320e15);
	odm_write_4byte(dm, 0x1b80, 0x5c320e17);
	odm_write_4byte(dm, 0x1b80, 0x54f00e25);
	odm_write_4byte(dm, 0x1b80, 0x54f00e27);
	odm_write_4byte(dm, 0x1b80, 0x6e180e35);
	odm_write_4byte(dm, 0x1b80, 0x6e180e37);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0e45);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0e47);
	odm_write_4byte(dm, 0x1b80, 0xe1860e55);
	odm_write_4byte(dm, 0x1b80, 0xe1860e57);
	odm_write_4byte(dm, 0x1b80, 0xe1b50e65);
	odm_write_4byte(dm, 0x1b80, 0xe1b50e67);
	odm_write_4byte(dm, 0x1b80, 0x6e480e75);
	odm_write_4byte(dm, 0x1b80, 0x6e480e77);
	odm_write_4byte(dm, 0x1b80, 0xe1860e85);
	odm_write_4byte(dm, 0x1b80, 0xe1860e87);
	odm_write_4byte(dm, 0x1b80, 0xe1b50e95);
	odm_write_4byte(dm, 0x1b80, 0xe1b50e97);
	odm_write_4byte(dm, 0x1b80, 0x5c320ea5);
	odm_write_4byte(dm, 0x1b80, 0x5c320ea7);
	odm_write_4byte(dm, 0x1b80, 0x54f10eb5);
	odm_write_4byte(dm, 0x1b80, 0x54f10eb7);
	odm_write_4byte(dm, 0x1b80, 0x0ba80ec5);
	odm_write_4byte(dm, 0x1b80, 0x0ba80ec7);
	odm_write_4byte(dm, 0x1b80, 0x6e880ed5);
	odm_write_4byte(dm, 0x1b80, 0x6e880ed7);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0ee5);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0ee7);
	odm_write_4byte(dm, 0x1b80, 0xe1860ef5);
	odm_write_4byte(dm, 0x1b80, 0xe1860ef7);
	odm_write_4byte(dm, 0x1b80, 0xe1b50f05);
	odm_write_4byte(dm, 0x1b80, 0xe1b50f07);
	odm_write_4byte(dm, 0x1b80, 0x5c320f15);
	odm_write_4byte(dm, 0x1b80, 0x5c320f17);
	odm_write_4byte(dm, 0x1b80, 0x54f10f25);
	odm_write_4byte(dm, 0x1b80, 0x54f10f27);
	odm_write_4byte(dm, 0x1b80, 0x0ba90f35);
	odm_write_4byte(dm, 0x1b80, 0x0ba90f37);
	odm_write_4byte(dm, 0x1b80, 0x6ec80f45);
	odm_write_4byte(dm, 0x1b80, 0x6ec80f47);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0f55);
	odm_write_4byte(dm, 0x1b80, 0x6f0f0f57);
	odm_write_4byte(dm, 0x1b80, 0xe1860f65);
	odm_write_4byte(dm, 0x1b80, 0xe1860f67);
	odm_write_4byte(dm, 0x1b80, 0xe1b50f75);
	odm_write_4byte(dm, 0x1b80, 0xe1b50f77);
	odm_write_4byte(dm, 0x1b80, 0x6ef80f85);
	odm_write_4byte(dm, 0x1b80, 0x6ef80f87);
	odm_write_4byte(dm, 0x1b80, 0xe1860f95);
	odm_write_4byte(dm, 0x1b80, 0xe1860f97);
	odm_write_4byte(dm, 0x1b80, 0xe1b50fa5);
	odm_write_4byte(dm, 0x1b80, 0xe1b50fa7);
	odm_write_4byte(dm, 0x1b80, 0x5c320fb5);
	odm_write_4byte(dm, 0x1b80, 0x5c320fb7);
	odm_write_4byte(dm, 0x1b80, 0x54f20fc5);
	odm_write_4byte(dm, 0x1b80, 0x54f20fc7);
	odm_write_4byte(dm, 0x1b80, 0x6e080fd5);
	odm_write_4byte(dm, 0x1b80, 0x6e080fd7);
	odm_write_4byte(dm, 0x1b80, 0x6f000fe5);
	odm_write_4byte(dm, 0x1b80, 0x6f000fe7);
	odm_write_4byte(dm, 0x1b80, 0xe1860ff5);
	odm_write_4byte(dm, 0x1b80, 0xe1860ff7);
	odm_write_4byte(dm, 0x1b80, 0xe1b51005);
	odm_write_4byte(dm, 0x1b80, 0xe1b51007);
	odm_write_4byte(dm, 0x1b80, 0x6e381015);
	odm_write_4byte(dm, 0x1b80, 0x6e381017);
	odm_write_4byte(dm, 0x1b80, 0xe1861025);
	odm_write_4byte(dm, 0x1b80, 0xe1861027);
	odm_write_4byte(dm, 0x1b80, 0xe1b51035);
	odm_write_4byte(dm, 0x1b80, 0xe1b51037);
	odm_write_4byte(dm, 0x1b80, 0xf9c81045);
	odm_write_4byte(dm, 0x1b80, 0xf9c81047);
	odm_write_4byte(dm, 0x1b80, 0x6e781055);
	odm_write_4byte(dm, 0x1b80, 0x6e781057);
	odm_write_4byte(dm, 0x1b80, 0xe1861065);
	odm_write_4byte(dm, 0x1b80, 0xe1861067);
	odm_write_4byte(dm, 0x1b80, 0xe1b51075);
	odm_write_4byte(dm, 0x1b80, 0xe1b51077);
	odm_write_4byte(dm, 0x1b80, 0xfacf1085);
	odm_write_4byte(dm, 0x1b80, 0xfacf1087);
	odm_write_4byte(dm, 0x1b80, 0x5c321095);
	odm_write_4byte(dm, 0x1b80, 0x5c321097);
	odm_write_4byte(dm, 0x1b80, 0x54f310a5);
	odm_write_4byte(dm, 0x1b80, 0x54f310a7);
	odm_write_4byte(dm, 0x1b80, 0x6eb810b5);
	odm_write_4byte(dm, 0x1b80, 0x6eb810b7);
	odm_write_4byte(dm, 0x1b80, 0xe18610c5);
	odm_write_4byte(dm, 0x1b80, 0xe18610c7);
	odm_write_4byte(dm, 0x1b80, 0xe1b510d5);
	odm_write_4byte(dm, 0x1b80, 0xe1b510d7);
	odm_write_4byte(dm, 0x1b80, 0x6ee810e5);
	odm_write_4byte(dm, 0x1b80, 0x6ee810e7);
	odm_write_4byte(dm, 0x1b80, 0xe18610f5);
	odm_write_4byte(dm, 0x1b80, 0xe18610f7);
	odm_write_4byte(dm, 0x1b80, 0xe1b51105);
	odm_write_4byte(dm, 0x1b80, 0xe1b51107);
	odm_write_4byte(dm, 0x1b80, 0x4d101115);
	odm_write_4byte(dm, 0x1b80, 0x4d101117);
	odm_write_4byte(dm, 0x1b80, 0x309d1125);
	odm_write_4byte(dm, 0x1b80, 0x309d1127);
	odm_write_4byte(dm, 0x1b80, 0x00011135);
	odm_write_4byte(dm, 0x1b80, 0x00011137);
	odm_write_4byte(dm, 0x1b80, 0x00061145);
	odm_write_4byte(dm, 0x1b80, 0x00061147);
	odm_write_4byte(dm, 0x1b80, 0x4d201155);
	odm_write_4byte(dm, 0x1b80, 0x4d201157);
	odm_write_4byte(dm, 0x1b80, 0x50381165);
	odm_write_4byte(dm, 0x1b80, 0x50381167);
	odm_write_4byte(dm, 0x1b80, 0x57f71175);
	odm_write_4byte(dm, 0x1b80, 0x57f71177);
	odm_write_4byte(dm, 0x1b80, 0x00071185);
	odm_write_4byte(dm, 0x1b80, 0x00071187);
	odm_write_4byte(dm, 0x1b80, 0x4b001195);
	odm_write_4byte(dm, 0x1b80, 0x4b001197);
	odm_write_4byte(dm, 0x1b80, 0x4e1f11a5);
	odm_write_4byte(dm, 0x1b80, 0x4e1f11a7);
	odm_write_4byte(dm, 0x1b80, 0x4f1511b5);
	odm_write_4byte(dm, 0x1b80, 0x4f1511b7);
	odm_write_4byte(dm, 0x1b80, 0x540111c5);
	odm_write_4byte(dm, 0x1b80, 0x540111c7);
	odm_write_4byte(dm, 0x1b80, 0x000411d5);
	odm_write_4byte(dm, 0x1b80, 0x000411d7);
	odm_write_4byte(dm, 0x1b80, 0x630011e5);
	odm_write_4byte(dm, 0x1b80, 0x630011e7);
	odm_write_4byte(dm, 0x1b80, 0x740011f5);
	odm_write_4byte(dm, 0x1b80, 0x740011f7);
	odm_write_4byte(dm, 0x1b80, 0x74021205);
	odm_write_4byte(dm, 0x1b80, 0x74021207);
	odm_write_4byte(dm, 0x1b80, 0x74001215);
	odm_write_4byte(dm, 0x1b80, 0x74001217);
	odm_write_4byte(dm, 0x1b80, 0x00041225);
	odm_write_4byte(dm, 0x1b80, 0x00041227);
	odm_write_4byte(dm, 0x1b80, 0xab001235);
	odm_write_4byte(dm, 0x1b80, 0xab001237);
	odm_write_4byte(dm, 0x1b80, 0x00011245);
	odm_write_4byte(dm, 0x1b80, 0x00011247);
	odm_write_4byte(dm, 0x1b80, 0x00061255);
	odm_write_4byte(dm, 0x1b80, 0x00061257);
	odm_write_4byte(dm, 0x1b80, 0x57f71265);
	odm_write_4byte(dm, 0x1b80, 0x57f71267);
	odm_write_4byte(dm, 0x1b80, 0x00071275);
	odm_write_4byte(dm, 0x1b80, 0x00071277);
	odm_write_4byte(dm, 0x1b80, 0x4b401285);
	odm_write_4byte(dm, 0x1b80, 0x4b401287);
	odm_write_4byte(dm, 0x1b80, 0x54011295);
	odm_write_4byte(dm, 0x1b80, 0x54011297);
	odm_write_4byte(dm, 0x1b80, 0x66ff12a5);
	odm_write_4byte(dm, 0x1b80, 0x66ff12a7);
	odm_write_4byte(dm, 0x1b80, 0x67fc12b5);
	odm_write_4byte(dm, 0x1b80, 0x67fc12b7);
	odm_write_4byte(dm, 0x1b80, 0x4e1712c5);
	odm_write_4byte(dm, 0x1b80, 0x4e1712c7);
	odm_write_4byte(dm, 0x1b80, 0x4f1112d5);
	odm_write_4byte(dm, 0x1b80, 0x4f1112d7);
	odm_write_4byte(dm, 0x1b80, 0x000412e5);
	odm_write_4byte(dm, 0x1b80, 0x000412e7);
	odm_write_4byte(dm, 0x1b80, 0x630012f5);
	odm_write_4byte(dm, 0x1b80, 0x630012f7);
	odm_write_4byte(dm, 0x1b80, 0x74001305);
	odm_write_4byte(dm, 0x1b80, 0x74001307);
	odm_write_4byte(dm, 0x1b80, 0x74021315);
	odm_write_4byte(dm, 0x1b80, 0x74021317);
	odm_write_4byte(dm, 0x1b80, 0x74001325);
	odm_write_4byte(dm, 0x1b80, 0x74001327);
	odm_write_4byte(dm, 0x1b80, 0x00041335);
	odm_write_4byte(dm, 0x1b80, 0x00041337);
	odm_write_4byte(dm, 0x1b80, 0xab001345);
	odm_write_4byte(dm, 0x1b80, 0xab001347);
	odm_write_4byte(dm, 0x1b80, 0x8b001355);
	odm_write_4byte(dm, 0x1b80, 0x8b001357);
	odm_write_4byte(dm, 0x1b80, 0xab001365);
	odm_write_4byte(dm, 0x1b80, 0xab001367);
	odm_write_4byte(dm, 0x1b80, 0xaa0c1375);
	odm_write_4byte(dm, 0x1b80, 0xaa0c1377);
	odm_write_4byte(dm, 0x1b80, 0x00011385);
	odm_write_4byte(dm, 0x1b80, 0x00011387);
	odm_write_4byte(dm, 0x1b80, 0x00061395);
	odm_write_4byte(dm, 0x1b80, 0x00061397);
	odm_write_4byte(dm, 0x1b80, 0x577713a5);
	odm_write_4byte(dm, 0x1b80, 0x577713a7);
	odm_write_4byte(dm, 0x1b80, 0x501813b5);
	odm_write_4byte(dm, 0x1b80, 0x501813b7);
	odm_write_4byte(dm, 0x1b80, 0x000713c5);
	odm_write_4byte(dm, 0x1b80, 0x000713c7);
	odm_write_4byte(dm, 0x1b80, 0x4b0013d5);
	odm_write_4byte(dm, 0x1b80, 0x4b0013d7);
	odm_write_4byte(dm, 0x1b80, 0x4e0213e5);
	odm_write_4byte(dm, 0x1b80, 0x4e0213e7);
	odm_write_4byte(dm, 0x1b80, 0x4f1913f5);
	odm_write_4byte(dm, 0x1b80, 0x4f1913f7);
	odm_write_4byte(dm, 0x1b80, 0x00041405);
	odm_write_4byte(dm, 0x1b80, 0x00041407);
	odm_write_4byte(dm, 0x1b80, 0x63051415);
	odm_write_4byte(dm, 0x1b80, 0x63051417);
	odm_write_4byte(dm, 0x1b80, 0x00011425);
	odm_write_4byte(dm, 0x1b80, 0x00011427);
	odm_write_4byte(dm, 0x1b80, 0x301d1435);
	odm_write_4byte(dm, 0x1b80, 0x301d1437);
	odm_write_4byte(dm, 0x1b80, 0x7b241445);
	odm_write_4byte(dm, 0x1b80, 0x7b241447);
	odm_write_4byte(dm, 0x1b80, 0x7a401455);
	odm_write_4byte(dm, 0x1b80, 0x7a401457);
	odm_write_4byte(dm, 0x1b80, 0x79001465);
	odm_write_4byte(dm, 0x1b80, 0x79001467);
	odm_write_4byte(dm, 0x1b80, 0x55031475);
	odm_write_4byte(dm, 0x1b80, 0x55031477);
	odm_write_4byte(dm, 0x1b80, 0x31501485);
	odm_write_4byte(dm, 0x1b80, 0x31501487);
	odm_write_4byte(dm, 0x1b80, 0x7b1c1495);
	odm_write_4byte(dm, 0x1b80, 0x7b1c1497);
	odm_write_4byte(dm, 0x1b80, 0x7a4014a5);
	odm_write_4byte(dm, 0x1b80, 0x7a4014a7);
	odm_write_4byte(dm, 0x1b80, 0x550b14b5);
	odm_write_4byte(dm, 0x1b80, 0x550b14b7);
	odm_write_4byte(dm, 0x1b80, 0x315014c5);
	odm_write_4byte(dm, 0x1b80, 0x315014c7);
	odm_write_4byte(dm, 0x1b80, 0x7b2014d5);
	odm_write_4byte(dm, 0x1b80, 0x7b2014d7);
	odm_write_4byte(dm, 0x1b80, 0x7a0014e5);
	odm_write_4byte(dm, 0x1b80, 0x7a0014e7);
	odm_write_4byte(dm, 0x1b80, 0x551314f5);
	odm_write_4byte(dm, 0x1b80, 0x551314f7);
	odm_write_4byte(dm, 0x1b80, 0x74011505);
	odm_write_4byte(dm, 0x1b80, 0x74011507);
	odm_write_4byte(dm, 0x1b80, 0x74001515);
	odm_write_4byte(dm, 0x1b80, 0x74001517);
	odm_write_4byte(dm, 0x1b80, 0x8e001525);
	odm_write_4byte(dm, 0x1b80, 0x8e001527);
	odm_write_4byte(dm, 0x1b80, 0x00011535);
	odm_write_4byte(dm, 0x1b80, 0x00011537);
	odm_write_4byte(dm, 0x1b80, 0x57021545);
	odm_write_4byte(dm, 0x1b80, 0x57021547);
	odm_write_4byte(dm, 0x1b80, 0x57001555);
	odm_write_4byte(dm, 0x1b80, 0x57001557);
	odm_write_4byte(dm, 0x1b80, 0x97001565);
	odm_write_4byte(dm, 0x1b80, 0x97001567);
	odm_write_4byte(dm, 0x1b80, 0x00011575);
	odm_write_4byte(dm, 0x1b80, 0x00011577);
	odm_write_4byte(dm, 0x1b80, 0x4f781585);
	odm_write_4byte(dm, 0x1b80, 0x4f781587);
	odm_write_4byte(dm, 0x1b80, 0x53881595);
	odm_write_4byte(dm, 0x1b80, 0x53881597);
	odm_write_4byte(dm, 0x1b80, 0xe16615a5);
	odm_write_4byte(dm, 0x1b80, 0xe16615a7);
	odm_write_4byte(dm, 0x1b80, 0x548015b5);
	odm_write_4byte(dm, 0x1b80, 0x548015b7);
	odm_write_4byte(dm, 0x1b80, 0x540015c5);
	odm_write_4byte(dm, 0x1b80, 0x540015c7);
	odm_write_4byte(dm, 0x1b80, 0xe16615d5);
	odm_write_4byte(dm, 0x1b80, 0xe16615d7);
	odm_write_4byte(dm, 0x1b80, 0x548115e5);
	odm_write_4byte(dm, 0x1b80, 0x548115e7);
	odm_write_4byte(dm, 0x1b80, 0x540015f5);
	odm_write_4byte(dm, 0x1b80, 0x540015f7);
	odm_write_4byte(dm, 0x1b80, 0xe1661605);
	odm_write_4byte(dm, 0x1b80, 0xe1661607);
	odm_write_4byte(dm, 0x1b80, 0x54821615);
	odm_write_4byte(dm, 0x1b80, 0x54821617);
	odm_write_4byte(dm, 0x1b80, 0x54001625);
	odm_write_4byte(dm, 0x1b80, 0x54001627);
	odm_write_4byte(dm, 0x1b80, 0xe1711635);
	odm_write_4byte(dm, 0x1b80, 0xe1711637);
	odm_write_4byte(dm, 0x1b80, 0xbf1d1645);
	odm_write_4byte(dm, 0x1b80, 0xbf1d1647);
	odm_write_4byte(dm, 0x1b80, 0x301d1655);
	odm_write_4byte(dm, 0x1b80, 0x301d1657);
	odm_write_4byte(dm, 0x1b80, 0xe1441665);
	odm_write_4byte(dm, 0x1b80, 0xe1441667);
	odm_write_4byte(dm, 0x1b80, 0xe1491675);
	odm_write_4byte(dm, 0x1b80, 0xe1491677);
	odm_write_4byte(dm, 0x1b80, 0xe14d1685);
	odm_write_4byte(dm, 0x1b80, 0xe14d1687);
	odm_write_4byte(dm, 0x1b80, 0xe1541695);
	odm_write_4byte(dm, 0x1b80, 0xe1541697);
	odm_write_4byte(dm, 0x1b80, 0xe1ac16a5);
	odm_write_4byte(dm, 0x1b80, 0xe1ac16a7);
	odm_write_4byte(dm, 0x1b80, 0x551316b5);
	odm_write_4byte(dm, 0x1b80, 0x551316b7);
	odm_write_4byte(dm, 0x1b80, 0xe15016c5);
	odm_write_4byte(dm, 0x1b80, 0xe15016c7);
	odm_write_4byte(dm, 0x1b80, 0x551516d5);
	odm_write_4byte(dm, 0x1b80, 0x551516d7);
	odm_write_4byte(dm, 0x1b80, 0xe15416e5);
	odm_write_4byte(dm, 0x1b80, 0xe15416e7);
	odm_write_4byte(dm, 0x1b80, 0xe1ac16f5);
	odm_write_4byte(dm, 0x1b80, 0xe1ac16f7);
	odm_write_4byte(dm, 0x1b80, 0x00011705);
	odm_write_4byte(dm, 0x1b80, 0x00011707);
	odm_write_4byte(dm, 0x1b80, 0x54bf1715);
	odm_write_4byte(dm, 0x1b80, 0x54bf1717);
	odm_write_4byte(dm, 0x1b80, 0x54c01725);
	odm_write_4byte(dm, 0x1b80, 0x54c01727);
	odm_write_4byte(dm, 0x1b80, 0x54a31735);
	odm_write_4byte(dm, 0x1b80, 0x54a31737);
	odm_write_4byte(dm, 0x1b80, 0x54c11745);
	odm_write_4byte(dm, 0x1b80, 0x54c11747);
	odm_write_4byte(dm, 0x1b80, 0x54a41755);
	odm_write_4byte(dm, 0x1b80, 0x54a41757);
	odm_write_4byte(dm, 0x1b80, 0x4c181765);
	odm_write_4byte(dm, 0x1b80, 0x4c181767);
	odm_write_4byte(dm, 0x1b80, 0xbf071775);
	odm_write_4byte(dm, 0x1b80, 0xbf071777);
	odm_write_4byte(dm, 0x1b80, 0x54c21785);
	odm_write_4byte(dm, 0x1b80, 0x54c21787);
	odm_write_4byte(dm, 0x1b80, 0x54a41795);
	odm_write_4byte(dm, 0x1b80, 0x54a41797);
	odm_write_4byte(dm, 0x1b80, 0xbf0417a5);
	odm_write_4byte(dm, 0x1b80, 0xbf0417a7);
	odm_write_4byte(dm, 0x1b80, 0x54c117b5);
	odm_write_4byte(dm, 0x1b80, 0x54c117b7);
	odm_write_4byte(dm, 0x1b80, 0x54a317c5);
	odm_write_4byte(dm, 0x1b80, 0x54a317c7);
	odm_write_4byte(dm, 0x1b80, 0xbf0117d5);
	odm_write_4byte(dm, 0x1b80, 0xbf0117d7);
	odm_write_4byte(dm, 0x1b80, 0xe1ba17e5);
	odm_write_4byte(dm, 0x1b80, 0xe1ba17e7);
	odm_write_4byte(dm, 0x1b80, 0x54df17f5);
	odm_write_4byte(dm, 0x1b80, 0x54df17f7);
	odm_write_4byte(dm, 0x1b80, 0x00011805);
	odm_write_4byte(dm, 0x1b80, 0x00011807);
	odm_write_4byte(dm, 0x1b80, 0x54bf1815);
	odm_write_4byte(dm, 0x1b80, 0x54bf1817);
	odm_write_4byte(dm, 0x1b80, 0x54e51825);
	odm_write_4byte(dm, 0x1b80, 0x54e51827);
	odm_write_4byte(dm, 0x1b80, 0x050a1835);
	odm_write_4byte(dm, 0x1b80, 0x050a1837);
	odm_write_4byte(dm, 0x1b80, 0x54df1845);
	odm_write_4byte(dm, 0x1b80, 0x54df1847);
	odm_write_4byte(dm, 0x1b80, 0x00011855);
	odm_write_4byte(dm, 0x1b80, 0x00011857);
	odm_write_4byte(dm, 0x1b80, 0x7f201865);
	odm_write_4byte(dm, 0x1b80, 0x7f201867);
	odm_write_4byte(dm, 0x1b80, 0x7e001875);
	odm_write_4byte(dm, 0x1b80, 0x7e001877);
	odm_write_4byte(dm, 0x1b80, 0x7d001885);
	odm_write_4byte(dm, 0x1b80, 0x7d001887);
	odm_write_4byte(dm, 0x1b80, 0x55011895);
	odm_write_4byte(dm, 0x1b80, 0x55011897);
	odm_write_4byte(dm, 0x1b80, 0x5c3118a5);
	odm_write_4byte(dm, 0x1b80, 0x5c3118a7);
	odm_write_4byte(dm, 0x1b80, 0xe15018b5);
	odm_write_4byte(dm, 0x1b80, 0xe15018b7);
	odm_write_4byte(dm, 0x1b80, 0xe15418c5);
	odm_write_4byte(dm, 0x1b80, 0xe15418c7);
	odm_write_4byte(dm, 0x1b80, 0x548018d5);
	odm_write_4byte(dm, 0x1b80, 0x548018d7);
	odm_write_4byte(dm, 0x1b80, 0x540018e5);
	odm_write_4byte(dm, 0x1b80, 0x540018e7);
	odm_write_4byte(dm, 0x1b80, 0xe15018f5);
	odm_write_4byte(dm, 0x1b80, 0xe15018f7);
	odm_write_4byte(dm, 0x1b80, 0xe1541905);
	odm_write_4byte(dm, 0x1b80, 0xe1541907);
	odm_write_4byte(dm, 0x1b80, 0x54811915);
	odm_write_4byte(dm, 0x1b80, 0x54811917);
	odm_write_4byte(dm, 0x1b80, 0x54001925);
	odm_write_4byte(dm, 0x1b80, 0x54001927);
	odm_write_4byte(dm, 0x1b80, 0xe1501935);
	odm_write_4byte(dm, 0x1b80, 0xe1501937);
	odm_write_4byte(dm, 0x1b80, 0xe1541945);
	odm_write_4byte(dm, 0x1b80, 0xe1541947);
	odm_write_4byte(dm, 0x1b80, 0x54821955);
	odm_write_4byte(dm, 0x1b80, 0x54821957);
	odm_write_4byte(dm, 0x1b80, 0x54001965);
	odm_write_4byte(dm, 0x1b80, 0x54001967);
	odm_write_4byte(dm, 0x1b80, 0xe1711975);
	odm_write_4byte(dm, 0x1b80, 0xe1711977);
	odm_write_4byte(dm, 0x1b80, 0xbfe91985);
	odm_write_4byte(dm, 0x1b80, 0xbfe91987);
	odm_write_4byte(dm, 0x1b80, 0x301d1995);
	odm_write_4byte(dm, 0x1b80, 0x301d1997);
	odm_write_4byte(dm, 0x1b80, 0x740219a5);
	odm_write_4byte(dm, 0x1b80, 0x740219a7);
	odm_write_4byte(dm, 0x1b80, 0x003f19b5);
	odm_write_4byte(dm, 0x1b80, 0x003f19b7);
	odm_write_4byte(dm, 0x1b80, 0x740019c5);
	odm_write_4byte(dm, 0x1b80, 0x740019c7);
	odm_write_4byte(dm, 0x1b80, 0x000219d5);
	odm_write_4byte(dm, 0x1b80, 0x000219d7);
	odm_write_4byte(dm, 0x1b80, 0x000119e5);
	odm_write_4byte(dm, 0x1b80, 0x000119e7);
	odm_write_4byte(dm, 0x1b80, 0x4d0419f5);
	odm_write_4byte(dm, 0x1b80, 0x4d0419f7);
	odm_write_4byte(dm, 0x1b80, 0x2ef81a05);
	odm_write_4byte(dm, 0x1b80, 0x2ef81a07);
	odm_write_4byte(dm, 0x1b80, 0x00001a15);
	odm_write_4byte(dm, 0x1b80, 0x00001a17);
	odm_write_4byte(dm, 0x1b80, 0x23301a25);
	odm_write_4byte(dm, 0x1b80, 0x23301a27);
	odm_write_4byte(dm, 0x1b80, 0x00241a35);
	odm_write_4byte(dm, 0x1b80, 0x00241a37);
	odm_write_4byte(dm, 0x1b80, 0x23e01a45);
	odm_write_4byte(dm, 0x1b80, 0x23e01a47);
	odm_write_4byte(dm, 0x1b80, 0x003f1a55);
	odm_write_4byte(dm, 0x1b80, 0x003f1a57);
	odm_write_4byte(dm, 0x1b80, 0x23fc1a65);
	odm_write_4byte(dm, 0x1b80, 0x23fc1a67);
	odm_write_4byte(dm, 0x1b80, 0xbfce1a75);
	odm_write_4byte(dm, 0x1b80, 0xbfce1a77);
	odm_write_4byte(dm, 0x1b80, 0x2ef01a85);
	odm_write_4byte(dm, 0x1b80, 0x2ef01a87);
	odm_write_4byte(dm, 0x1b80, 0x00001a95);
	odm_write_4byte(dm, 0x1b80, 0x00001a97);
	odm_write_4byte(dm, 0x1b80, 0x4d001aa5);
	odm_write_4byte(dm, 0x1b80, 0x4d001aa7);
	odm_write_4byte(dm, 0x1b80, 0x00011ab5);
	odm_write_4byte(dm, 0x1b80, 0x00011ab7);
	odm_write_4byte(dm, 0x1b80, 0x549f1ac5);
	odm_write_4byte(dm, 0x1b80, 0x549f1ac7);
	odm_write_4byte(dm, 0x1b80, 0x54ff1ad5);
	odm_write_4byte(dm, 0x1b80, 0x54ff1ad7);
	odm_write_4byte(dm, 0x1b80, 0x54001ae5);
	odm_write_4byte(dm, 0x1b80, 0x54001ae7);
	odm_write_4byte(dm, 0x1b80, 0x00011af5);
	odm_write_4byte(dm, 0x1b80, 0x00011af7);
	odm_write_4byte(dm, 0x1b80, 0x5c311b05);
	odm_write_4byte(dm, 0x1b80, 0x5c311b07);
	odm_write_4byte(dm, 0x1b80, 0x07141b15);
	odm_write_4byte(dm, 0x1b80, 0x07141b17);
	odm_write_4byte(dm, 0x1b80, 0x54001b25);
	odm_write_4byte(dm, 0x1b80, 0x54001b27);
	odm_write_4byte(dm, 0x1b80, 0x5c321b35);
	odm_write_4byte(dm, 0x1b80, 0x5c321b37);
	odm_write_4byte(dm, 0x1b80, 0x00011b45);
	odm_write_4byte(dm, 0x1b80, 0x00011b47);
	odm_write_4byte(dm, 0x1b80, 0x5c321b55);
	odm_write_4byte(dm, 0x1b80, 0x5c321b57);
	odm_write_4byte(dm, 0x1b80, 0x07141b65);
	odm_write_4byte(dm, 0x1b80, 0x07141b67);
	odm_write_4byte(dm, 0x1b80, 0x54001b75);
	odm_write_4byte(dm, 0x1b80, 0x54001b77);
	odm_write_4byte(dm, 0x1b80, 0x5c311b85);
	odm_write_4byte(dm, 0x1b80, 0x5c311b87);
	odm_write_4byte(dm, 0x1b80, 0x00011b95);
	odm_write_4byte(dm, 0x1b80, 0x00011b97);
	odm_write_4byte(dm, 0x1b80, 0x4c981ba5);
	odm_write_4byte(dm, 0x1b80, 0x4c981ba7);
	odm_write_4byte(dm, 0x1b80, 0x4c181bb5);
	odm_write_4byte(dm, 0x1b80, 0x4c181bb7);
	odm_write_4byte(dm, 0x1b80, 0x00011bc5);
	odm_write_4byte(dm, 0x1b80, 0x00011bc7);
	odm_write_4byte(dm, 0x1b80, 0x5c321bd5);
	odm_write_4byte(dm, 0x1b80, 0x5c321bd7);
	odm_write_4byte(dm, 0x1b80, 0x62041be5);
	odm_write_4byte(dm, 0x1b80, 0x62041be7);
	odm_write_4byte(dm, 0x1b80, 0x63031bf5);
	odm_write_4byte(dm, 0x1b80, 0x63031bf7);
	odm_write_4byte(dm, 0x1b80, 0x66071c05);
	odm_write_4byte(dm, 0x1b80, 0x66071c07);
	odm_write_4byte(dm, 0x1b80, 0x7b201c15);
	odm_write_4byte(dm, 0x1b80, 0x7b201c17);
	odm_write_4byte(dm, 0x1b80, 0x7a001c25);
	odm_write_4byte(dm, 0x1b80, 0x7a001c27);
	odm_write_4byte(dm, 0x1b80, 0x79001c35);
	odm_write_4byte(dm, 0x1b80, 0x79001c37);
	odm_write_4byte(dm, 0x1b80, 0x7f201c45);
	odm_write_4byte(dm, 0x1b80, 0x7f201c47);
	odm_write_4byte(dm, 0x1b80, 0x7e001c55);
	odm_write_4byte(dm, 0x1b80, 0x7e001c57);
	odm_write_4byte(dm, 0x1b80, 0x7d001c65);
	odm_write_4byte(dm, 0x1b80, 0x7d001c67);
	odm_write_4byte(dm, 0x1b80, 0x09011c75);
	odm_write_4byte(dm, 0x1b80, 0x09011c77);
	odm_write_4byte(dm, 0x1b80, 0x0c011c85);
	odm_write_4byte(dm, 0x1b80, 0x0c011c87);
	odm_write_4byte(dm, 0x1b80, 0x0ba61c95);
	odm_write_4byte(dm, 0x1b80, 0x0ba61c97);
	odm_write_4byte(dm, 0x1b80, 0x00011ca5);
	odm_write_4byte(dm, 0x1b80, 0x00011ca7);
	odm_write_4byte(dm, 0x1b80, 0x00000006);
	odm_write_4byte(dm, 0x1b80, 0x00000002);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK NCTL setting!!!\n");
}

void _dpk_mac_bb_setting_8195b(struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, 0x522, 0xff);
	odm_set_bb_reg(dm, 0x1518, BIT(16), 0x1);
	odm_set_bb_reg(dm, 0x550, BIT(11) | BIT(3), 0x0);
	odm_set_bb_reg(dm, 0x90c, BIT(15), 0x1);
	/*0x90c[15]=1: dac_buf reset selection*/

	odm_set_bb_reg(dm, 0xc94, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0xc94, (BIT(11) | BIT(10)), 0x1);
	/* 3-wire off*/
	odm_write_4byte(dm, 0xc00, 0x00000004);
	/*disable PMAC*/
	odm_set_bb_reg(dm, 0xb00, BIT(8), 0x0);
	/*	RF_DBG(dm, DBG_RF_IQK, ("[IQK]Set MACBB setting for IQK\n"));*/
#if 0
	/*disable CCK block*/
	odm_set_bb_reg(dm, R_0x808, BIT(28), 0x0);
	/*disable OFDM CCA*/
	odm_set_bb_reg(dm, R_0x838, BIT(3) | BIT(2) | BIT(1), 0x7);
	/*1c44[16]: iqk_clock [17]: rest*/
	odm_set_bb_reg(dm, 0x1c44, BIT(17) | BIT(16), 0x3);
	/*1904[17]: en_iqk_dpk*/
	odm_set_bb_reg(dm, 0x1904, BIT(17), 0x1);
#endif
	RF_DBG(dm, DBG_RF_DPK, "[DPK] MAC/BB setting for DPK mode\n");
}

void _dpk_manual_txagc_8195b(struct dm_struct *dm, boolean is_manual)
{
	//u8 i=0x0;
	//for (i = 0; i < 0x14; i++)
	//odm_write_4byte(dm, 0x1d00 | (i << 4), 0xffffffff);
	//u8 hw_rate, tmp;
	odm_set_bb_reg(dm, 0xc68, BIT(11), is_manual);
	odm_set_bb_reg(dm, 0xc68, 0x3f, 0x22);
}

void _dpk_rfsetting_8195b(struct dm_struct *dm, u8 rf_bandtype)
{
	struct dm_iqk_info	*iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	u32 rf_reg00 = 0x0l;
	u8 path = 0x0;
	u8 txagc_init = 0x1c; /* DPK TXAGC value*/
	u8 eethermal = 0x0;
	u8 curr_thermal = 0x0;
	u8 diff_thermal = 0x0;

	eethermal = rf->eeprom_thermal;
	curr_thermal = _dpk_get_thermal_8195b(dm, path);
	diff_thermal = HALRF_ABS(eethermal, curr_thermal) / 6;
	odm_write_4byte(dm, 0x1b00, 0x00000008);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);

	if (rf_bandtype == ODM_BAND_2_4G) {
		txagc_init = 0x1c;
		if (eethermal == 0x0)
			txagc_init = 0x1c;
		else if (eethermal > curr_thermal) // decrease
			txagc_init = txagc_init - diff_thermal;
		else
			txagc_init = txagc_init + diff_thermal;

		rf_reg00 = 0x50000 + txagc_init; /* set TXAGC value*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x8F, RFREGOFFSETMASK, 0xA8040);
		odm_set_rf_reg(dm, RF_PATH_A, 0x00, RFREGOFFSETMASK, rf_reg00);
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, RFREGOFFSETMASK, 0x9b222);
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, RFREGOFFSETMASK, 0x0526a);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, RFREGOFFSETMASK, 0x0118C);
	} else {
		txagc_init = 0x1a;//bw20
		if (eethermal == 0x0)
			txagc_init = 0x1a;
		else if (eethermal > curr_thermal) // decrease
			txagc_init = txagc_init - diff_thermal;
		else
			txagc_init = txagc_init + diff_thermal;

		rf_reg00 = 0x50000 + txagc_init; /* set TXAGC value*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x8F, RFREGOFFSETMASK, 0xA8040);
		odm_set_rf_reg(dm, RF_PATH_A, 0x00, RFREGOFFSETMASK, rf_reg00);
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, RFREGOFFSETMASK, 0x9b222);
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, RFREGOFFSETMASK, 0x0526a);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, RFREGOFFSETMASK, 0x0108C);
	}
#if 1
	RF_DBG(dm, DBG_RF_DPK, "txagc_init = %x\n", txagc_init);
	RF_DBG(dm, DBG_RF_DPK, "eethermal = %x\n", eethermal);
	RF_DBG(dm, DBG_RF_DPK, "curr_thermal = %x\n", curr_thermal);
	RF_DBG(dm, DBG_RF_DPK, "diff_thermal = %x\n", diff_thermal);
	RF_DBG(dm, DBG_RF_DPK, "abs= %x\n", HALRF_ABS(eethermal, curr_thermal));
#endif
	ODM_sleep_ms(1);
}

void _dpk_afe_setting_8195b(struct dm_struct *dm, boolean is_do_dpk)
{
	RF_DBG(dm, DBG_RF_DPK, "\n");
	if (is_do_dpk) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] AFE setting for DPK mode\n");
		/*AFE setting*/
#if 0
		odm_write_4byte(dm, 0xc34, 0xC10AA254);
		odm_write_4byte(dm, 0xc60, 0x70000000);
		odm_write_4byte(dm, 0xc60, 0x700F0040);
		odm_write_4byte(dm, 0x808, 0x2D028200);
		odm_write_4byte(dm, 0x810, 0x20101063);
		odm_write_4byte(dm, 0x90c, 0x0B00C000);
		odm_write_4byte(dm, 0x9a4, 0x00000080);
#else
		odm_write_4byte(dm, 0x34, 0xC10AA254);
		odm_write_4byte(dm, 0xc58, 0xE4012C92);
		odm_write_4byte(dm, 0xc5c, 0xF05E0002);
		odm_write_4byte(dm, 0xc6c, 0x00000003);
		odm_write_4byte(dm, 0xC60, 0x70000000);
		odm_write_4byte(dm, 0xC60, 0x700F0040);
		odm_write_4byte(dm, 0x808, 0x2D028200);
		odm_write_4byte(dm, 0x810, 0x20101063);
		odm_write_4byte(dm, 0x90c, 0x0B00C000);
		odm_write_4byte(dm, 0x9a4, 0x00000080);
		odm_write_4byte(dm, 0x1904, 0x00020000);
		odm_write_4byte(dm, 0xc00, 0x00000004);
#endif
	} else {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]AFE setting for Normal mode\n");
#if 0
		odm_write_4byte(dm, 0xc60, 0x70000000);
		odm_write_4byte(dm, 0xc60, 0x70070040);
#endif
		odm_set_bb_reg(dm, 0x1b0c, BIT(13) | BIT(12), 0x0);
		odm_set_bb_reg(dm, 0x1bcc, 0x1f, 0x0);
		odm_write_4byte(dm, 0xc58, 0xE4012E92);
		odm_write_4byte(dm, 0xc5c, 0xF05E0002);
		odm_write_4byte(dm, 0xC6C, 0x0000122B);
		odm_write_4byte(dm, 0x034, 0xC10AA254);
		odm_write_4byte(dm, 0x808, 0x34028211);
		odm_write_4byte(dm, 0x810, 0x21104285);
		odm_write_4byte(dm, 0x90c, 0x13000400);
		odm_write_4byte(dm, 0x9a4, 0x80000088);
		odm_write_4byte(dm, 0x1904, 0x00238000);
		odm_write_4byte(dm, 0xc00, 0x0000007);
	}
}

void _dpk_con_tx_8195b(struct dm_struct *dm, boolean is_contx)
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

void _dpk_set_group_8195b(struct dm_struct *dm, u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	if (group < G_2G_N)
		_dpk_rfsetting_8195b(dm, ODM_BAND_2_4G);
	else
		_dpk_rfsetting_8195b(dm, ODM_BAND_5G);
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to group%d, RF0x18 = 0x%x\n",
	       group, odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK));
#endif
}

void _dpk_txk_setting_8195b(struct dm_struct *dm, u8 path)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	odm_write_4byte(dm, 0x1b00, 0x00000008 | path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_bb_reg(dm, 0x1b0c, BIT(13) | BIT(12), 0x0);//disable dbg
	odm_set_rf_reg(dm, path, 0xde, BIT(16), 0x1);
	odm_set_rf_reg(dm, path, 0xee, BIT(18), 0x0);
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_set_rf_reg(dm, path, 0x56, 0x00fff, 0xee6);
		odm_set_rf_reg(dm, path, 0x8f, 0xfffff, 0xafc00);
		odm_write_1byte(dm, 0x1bcc, 0x09);
		break;
	case ODM_BAND_5G:
		if (*dm->band_width == 2)
			odm_write_1byte(dm, 0x1bcc, 0x9);
		else
			odm_write_1byte(dm, 0x1bcc, 0x12);
		odm_set_rf_reg(dm, path, 0x56, 0xfff, 0xee6);
		odm_set_rf_reg(dm, path, 0x8f, 0xfffff, 0xafc00);
		break;
	}
	odm_set_bb_reg(dm, 0x1b0c, BIT(13) | BIT(12), 0x0);//disable dbg
	odm_set_bb_reg(dm, 0x1b2c, 0x00000fff, 0x032);
}

boolean _dpk_one_shot_8195b(struct dm_struct *dm, u8 path, u8 action)
{
	u8 temp = 0x0;
	u16 dpk_cmd = 0x0;
	boolean result;

	if (action == GAIN_LOSS)
		dpk_cmd = 0x1118;
	else if (action == DO_DPK)
		dpk_cmd = 0x1218;
	else if (action == DPK_ON)
		dpk_cmd = 0x1318;
	else if (action == DPK_LOK)
		dpk_cmd = 0x00000008 | (1 << (4 + path));
	else if (action == DPK_TXK)
		dpk_cmd = 0x00000008 | ((*dm->band_width + 4) << 8) |
			  (1 << (path + 4));

	RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot dpk_cmd = 0x%x\n", dpk_cmd);
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd);
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, dpk_cmd + 1);
	ODM_delay_ms(1);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] one-shot done\n");
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
	result = _dpk_check_nctl_done_8195b(dm, path, dpk_cmd);
	return result;
}

u8 _dpk_pas_gain_check_8195b(struct dm_struct *dm, u8 path)
{
	u8 result;
	u32 i_val = 0, q_val = 0;

	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);

	odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e038);
	//odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00290000);
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00060000);

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
	return result;
}

void _dpk_pas_read_8195b(struct dm_struct *dm, boolean is_gainloss, u8 path)
{
	u8 k, j;
	u32 reg_1bfc, tmp, reg_1b90;

	RF_DBG(dm, DBG_RF_DPK, "\n");
	//backup 0x1b90
	reg_1b90 = odm_get_bb_reg(dm, R_0x1b90, MASKDWORD);
	if (is_gainloss) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_PAS_GL_read_8195b\n");
		odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);
		tmp = 0x0105e038;
	} else {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_DPK_read_8195b\n");
		tmp = 0x0109e038;
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] 0x1bcc = 0x%x, 0x1b90 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0x1bcc, MASKDWORD),
	       odm_get_bb_reg(dm, R_0x1b90, MASKDWORD));
	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, (tmp | k));
		odm_write_4byte(dm, 0x1bd4, 0x00060000);
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
		odm_write_4byte(dm, 0x1bd4, 0x00070000);
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
		odm_write_4byte(dm, 0x1bd4, 0x00080000);
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
		odm_write_4byte(dm, 0x1bd4, 0x00090000);
		reg_1bfc = odm_read_4byte(dm, R_0x1bfc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] 1bfc = 0x%x\n", reg_1bfc);
	}
	//restore 1b90
	odm_write_4byte(dm, 0x1b90, reg_1b90);
	RF_DBG(dm, DBG_RF_DPK, "\n");
}

u8 _dpk_gainloss_8195b(struct dm_struct *dm, u8 path)
{
	u8 k = 0x0, tx_agc_search = 0x0, result[5] = {0x0};
	s8 txidx_offset = 0x0;
	u8 thermal_value;
	u8 i;
	u32 rf63;

	//ODM_delay_ms(1);
	odm_write_4byte(dm, 0x1b00, 0x00000008 | path << 1);
	odm_write_1byte(dm, R_0x1b92, 0x05);
	odm_write_4byte(dm, 0x1b98, 0x41382e21);
	odm_write_1byte(dm, 0x1b8d, 0x40);

	for (k = 0; k < 1; k++) {
		_dpk_one_shot_8195b(dm, path, GAIN_LOSS);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00060000);
		result[k] = (u8)odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] result[%d] = 0x%x\n",
		       k, result[k]);
		tx_agc_search = result[k];
	}

	//store Rf0x63
	odm_set_rf_reg(dm, RF_PATH_A, 0x63, RFREGOFFSETMASK, 0x0526a);
	rf63 = odm_get_rf_reg(dm, (enum rf_path)path, 0x63, 0xfffff);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] restore rf63 = 0x%x\n", rf63);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] TXAGC_search_S%d = 0x%x\n",
	       path, tx_agc_search);
	odm_set_bb_reg(dm, 0x1bcc, BIT(16), 0x0);
	if (DPK_PAS_DBG_8195B)
		_dpk_pas_read_8195b(dm, true, path);

	return tx_agc_search;
}

boolean _dpk_by_path_8195b(struct dm_struct *dm, u8 tn, u8 path, u8 gp)
{
	u32 reg_1bd0;
	u8 tx_agc = 0x0, pwsf_idx = 0, tx_agc_ori = 0x0;
	boolean result = false;

	tx_agc_ori = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x00, 0x0001f);

	if (gp == 5 || gp == 8) /*5G High Bnad*/
		tx_agc = tx_agc_ori + tn - 0xa;
	else
		tx_agc = tx_agc_ori + tn - 0xa;

	if (tx_agc >= 0x19)
		pwsf_idx = tx_agc - 0x19;
	else
		pwsf_idx = 0x20 - (0x19 - tx_agc);

#if 0
	if (pwsf_idx > 0xa) {
		if (pwsf_idx < 0x1e)
			pwsf_idx = 0x1e;
	} else {
		if (pwsf_idx > 0x2)
			pwsf_idx = 0x02;
	}
#endif
#if 0
	//pwsf_idx = 0x1f;
	//tx_agc = 0x18;
#endif
	/*TXAGC for DPK*/
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x00, RFREG_MASK,
		       (0x50000 | tx_agc));
	ODM_delay_ms(1);
	//ODM_delay_us(600);

	odm_write_1byte(dm, R_0x1b92, 0x05);
	pwsf_idx++;

	reg_1bd0 = 0x00000000 | ((pwsf_idx & 0x1f) << 8);

	odm_set_bb_reg(dm, R_0x1bd0, MASKDWORD, reg_1bd0);
	odm_write_4byte(dm, 0x1b98, 0x41382e21);

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][DO_DPK] pwsf_idx=0x%x,tx_agc=0x%x,0x1bd0[12:8]=0x%x\n",
	       pwsf_idx, tx_agc, odm_get_bb_reg(dm, R_0x1bd0, 0x00001F00));
	result = _dpk_one_shot_8195b(dm, path, DO_DPK);
#if 0
#if 1
	result = (u8)odm_get_bb_reg(dm, R_0x1b08, BIT(26));
#else
	//read DPK fail report
	odm_set_bb_reg(dm, 0x1bcc, BIT(26), 0x0);
	odm_write_1byte(dm, 0x1bd6, 0xa);
	result = (boolean)(BIT(0) & odm_read_4byte(dm, 0x1bfc));
#endif
#endif
	//restore for IQK
	odm_set_bb_reg(dm, 0x1bcc, BIT(16), 0x0);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][DO_DPK] fail bit = %x\n", result);

	if (DPK_PAS_DBG_8195B)
		_dpk_pas_read_8195b(dm, false, path);

	return result;
}

boolean _dpk_iq_check_8195b(struct dm_struct *dm, u8 addr, u32 reg_1bfc)
{
	u32 i_val = 0, q_val = 0;

	return 0;
#if 0
	if (DPK_SRAM_IQ_DBG_8195B && addr < 16)
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

void _dpk_on_8195b(struct dm_struct *dm, u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	boolean result = false;

	odm_write_4byte(dm, 0x1b38, 0x20000000);
	odm_write_4byte(dm, 0x1b3c, 0x20000000);

	result = _dpk_one_shot_8195b(dm, path, DPK_ON);

	/*I_Gain @ 1b98[31:16], Q_Gain @ 1b98[15:0]*/
	odm_set_bb_reg(dm, R_0x1b98, MASKDWORD, 0x50925092);
	/*[12] TX CCK mode DPD enable*/
	odm_set_bb_reg(dm, R_0x1bcc, BIT(13) | BIT(12), 0x0);

	/*add for no DPK, read LUT from flash directly*/
	odm_set_bb_reg(dm, 0xc94, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0xc94, BIT(10), 0x1);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPD enable!!!\n\n", path);
}

u8 dpk_channel_transfer_8195b(void *dm_void)
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
			else if (channel >= 100 && channel <= 104)
				i = 4;
			else if (channel > 104 && channel <= 144)
				i = 5;
			else if (channel > 144 && channel <= 161)
				i = 6;
			else if (channel > 161 && channel <= 173)
				i = 7;
			else if (channel > 173)
				i = 8;
		} else if (bandwidth == 0x2) { //BW80
			if (channel <= 42)
				i = 9;
			else if (channel >= 43 && channel <= 58)
				i = 10;
			else if (channel >= 59 && channel <= 106)
				i = 11;
			else if (channel >= 107 && channel <= 122)
				i = 12;
			else if (channel >= 123 && channel <= 138)
				i = 13;
			else if (channel >= 139 && channel <= 155)
				i = 14;
			else if (channel >= 156)
				i = 15;
		}
	}
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] channel = %d, bandwidth = %d, transfer idx = %d\n",
	       channel, bandwidth, i);
	return i;
}

void dpk_sram_read_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, addr;
	u32 tmp1 = 0x0, tmp2 = 0x0, tmp3 = 0x0, tmp4 = 0x0;
	u8 tmp5 = G_2G_N, tmp6 = G_5G_N;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Start =========\n");
	path = 0x0;
	for (group = 0; group < DPK_GROUP_NUM_8195B; group++) {
		for (addr = 0; addr < 16; addr++) {
			if (group < 3)
				tmp1 = dpk_info->lut_2g_even[path][group][addr];
			else
				tmp1 =
				dpk_info->lut_5g_even[path][group - tmp5][addr];
			if (DPK_PAS_DBG_8195B)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read 2G S%d[%d]even[%2d]= 0x%x\n",
				       path, group, addr, tmp1);
			}
		for (addr = 0; addr < 16; addr++) {
			if (group < 3)
				tmp2 = dpk_info->lut_2g_odd[path][group][addr];
			else
				tmp2 =
				dpk_info->lut_5g_odd[path][group - tmp5][addr];
			if (DPK_PAS_DBG_8195B)
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] Read 2G S%d[%d] odd[%2d]= 0x%x\n",
				       path, group, addr, tmp2);
			}
		}
	RF_DBG(dm, DBG_RF_DPK, "[DPK] ===== SRAM Read Finish =====\n");
}

u8 _dpk_lut_sram_read_8195b(void *dm_void, u8 group, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, i, j = G_2G_N;
	u32 reg_1bdc = 0, reg_1bfc = 0;
	u8 sram_value = 0x1;

	odm_write_4byte(dm, 0x1b00, 0xf8000008);
	odm_write_4byte(dm, 0x1b08, 0x00000080);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]group= 0x%x, path = 0x%x\n",
	       group, path);

	/*even*/
	odm_write_4byte(dm, 0x1bd4, 0x00040001);
	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK][even] 1bdc = 0x%x, 1bfc = 0x%x\n",
		       reg_1bdc, reg_1bfc);
#endif
#if 1
		addr = (i - 1) / 2;
		if (_dpk_iq_check_8195b(dm, addr, reg_1bfc)) {
			sram_value = 0;
		} else {
			if (group < G_2G_N)
				dpk_info->lut_2g_even[path][group][addr] =
								       reg_1bfc;
			else
				dpk_info->lut_5g_even[path][group - j][addr] =
								       reg_1bfc;
		}
#endif
	}
	/*odd*/
	odm_write_4byte(dm, 0x1bd4, 0x00050001);
	for (i = 1; i < 0x20; i += 2) {
		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0xc0000080 | i);
		reg_1bdc = odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD);
		reg_1bfc = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK][ odd] 1bdc = 0x%x, 1bfc = 0x%x\n",
		       reg_1bdc, reg_1bfc);
#endif
#if 1
		addr = (i - 1) / 2;
		if (_dpk_iq_check_8195b(dm, addr, reg_1bfc)) {
			sram_value = 0;
		} else {
			if (group < G_2G_N)
				dpk_info->lut_2g_odd[path][group][addr] =
								       reg_1bfc;
			else
				dpk_info->lut_5g_odd[path][group - j][addr] =
								       reg_1bfc;
		}
#endif
	}
	odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
// read back sram
#if 1
	for (i = 1; i < 0x20; i += 2) {
		addr = (i - 1) / 2;
		if (group < G_2G_N)
			RF_DBG(dm, DBG_RF_DPK, "[DPK]2g_e[%x][%x][%x] = 0x%x\n",
			       path, group, addr,
			       dpk_info->lut_2g_even[path][group][addr]);
		else
			RF_DBG(dm, DBG_RF_DPK, "[DPK]5g_e[%x][%x][%x] = 0x%x\n",
			       path, group - j, addr,
			       dpk_info->lut_5g_even[path][group - j][addr]);
	}

	for (i = 1; i < 0x20; i += 2) {
		addr = (i - 1) / 2;
		if (group < G_2G_N)
			RF_DBG(dm, DBG_RF_DPK, "[DPK]2g_o[%x][%x][%x] = 0x%x\n",
			       path, group, addr,
			       dpk_info->lut_2g_odd[path][group][addr]);
		else
			RF_DBG(dm, DBG_RF_DPK, "[DPK]5g_o[%x][%x][%x] = 0x%x\n",
			       path, group - j, addr,
			       dpk_info->lut_5g_odd[path][group - j][addr]);
	}
#endif
	return sram_value;
}

void _dpk_lut_sram_write_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, group, path;
	u32 reg_1bdc_even, reg_1bdc_odd, temp1, temp2, temp3;
	u8 j = G_2G_N;
#if 1
	group = dpk_channel_transfer_8195b(dm);
#else
	if (*dm->band_type == ODM_BAND_2_4G)
		group = 0;
	else
		group = 0x3;
#endif
	reg_1bdc_even = 0xc0000000;
	reg_1bdc_odd = 0x80000080;
	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));
		/*write_even*/
		for (addr = 0; addr < 16; addr++) {
			if (group < G_2G_N)
				temp1 = dpk_info->lut_2g_even[path][group][addr]
				;
			else
				temp1 =
				   dpk_info->lut_5g_even[path][group - j][addr];
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_even | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));
#if (DPK_SRAM_write_DBG_8195B)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d] even[%2d]= 0x%x\n",
			       path, group, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));
#endif
		}

		/*write_odd*/
		for (addr = 0; addr < 16; addr++) {
			if (group < G_2G_N)
				temp1 = dpk_info->lut_2g_odd[path][group][addr];
			else
				temp1 =
				     dpk_info->lut_5g_odd[path][group - j][addr]
									       ;
			temp2 = (temp1 & 0x3FFFFF) << 8;
			temp3 = reg_1bdc_odd | temp2;
			odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, temp3 |
				       (addr * 2 + 1));

#if (DPK_SRAM_write_DBG_8195B)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S%d[%d]  odd[%2d]= 0x%x\n",
			       path, group, addr,
			       odm_get_bb_reg(dm, R_0x1bdc, MASKDWORD));
#endif
		}

		odm_set_bb_reg(dm, R_0x1bdc, MASKDWORD, 0x00000000);
		if (group < G_2G_N) {
			odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00,
				       dpk_info->pwsf_2g[path][group]);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] W S%d[%d] pwsf = 0x%x\n",
			       path, group, dpk_info->pwsf_2g[path][group]);
		} else {
			odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00,
				       dpk_info->pwsf_5g[path][group - G_2G_N]);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] W S%d[%d] pwsf = 0x%x\n",
			       path, group,
			       dpk_info->pwsf_5g[path][group - G_2G_N]);
		}
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S%d[%d] 0x1bd0 = 0x%x\n",
		       path, group, odm_get_bb_reg(dm, R_0x1bd0, 0x00001f00));
	}
#if 0
	path = 0x0;
	_dpk_lut_sram_read_8195b(dm, group, path);
#endif
}

u8 _dpk_check_fail_8195b(struct dm_struct *dm, boolean is_fail, u8 path,
			 u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 result = 0;

	if (!is_fail) {
		if (_dpk_lut_sram_read_8195b(dm, group, path)) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] = S%d[%d] sram read PASS =\n",
			       path, group);
			if (group < G_2G_N) {
				dpk_info->pwsf_2g[path][group] =
				(u8)odm_get_bb_reg(dm, R_0x1bd0, 0x00001F00);
				dpk_info->dpk_2g_result[path][group] = 1;
			} else {
				dpk_info->pwsf_5g[path][group - G_2G_N] =
				(u8)odm_get_bb_reg(dm, R_0x1bd0, 0x00001F00);
				dpk_info->dpk_5g_result[path][group - G_2G_N] =
									      1;
			}
			result = 1;
		} else {
			if (group < G_2G_N) {
				dpk_info->pwsf_2g[path][group] = 0;
				dpk_info->dpk_2g_result[path][group] = 0;
			} else {
				dpk_info->pwsf_5g[path][group - G_2G_N] = 0;
				dpk_info->dpk_5g_result[path][group - G_2G_N] =
									      0;
			}
			result = 0;
		}
	} else {
		dpk_info->pwsf_2g[path][group] = 0;
		dpk_info->pwsf_5g[path][group - G_2G_N] = 0;
		dpk_info->dpk_2g_result[path][group] = 0;
		dpk_info->dpk_5g_result[path][group - G_2G_N] = 0;
		result = 0;
	}
	return result;
}

void _dpk_result_reset_8195b(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path = 0x0, group = 0x0, i;

	/*dpk_info->is_dpk_path_ok[path] = 0;*/
	dpk_info->dpk_path_ok = 0;

	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		for (group = 0; group < G_2G_N; group++) {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_2g_result[path][group] = 0;
		}
		for (group = 0; group < G_5G_N; group++) {
			dpk_info->pwsf_5g[path][group] = 0;
			dpk_info->dpk_5g_result[path][group] = 0;
		}
	}
}

u8 _dpk_calibrate_8195b(struct dm_struct *dm, u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 dpk_fail = 1, tx_agc_search = 0;
	u8 group, retry_cnt = 0x0, result;
	boolean is_2g_fail = false;
	boolean is_5g_fail = false;

	for (group = 0; group < DPK_GROUP_NUM_8195B; group++) {
		_dpk_set_group_8195b(dm, group);

		RF_DBG(dm, DBG_RF_DPK, "\n");
		for (retry_cnt = 0; retry_cnt < 6; retry_cnt++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK]Group %d retry =%d\n", group, retry_cnt);
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] = S%d[%d] DPK Start =\n", path, group);
			//ODM_delay_ms(10);
			tx_agc_search = _dpk_gainloss_8195b(dm, path);
			//ODM_delay_ms(10);
			dpk_fail = _dpk_by_path_8195b(dm, tx_agc_search,
						      path, group);
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] = S%d[%d] DPK Finish =\n", path, group);
			result =
			_dpk_check_fail_8195b(dm, dpk_fail, path, group);
			if (result)
				break;
		}
		RF_DBG(dm, DBG_RF_DPK, "\n");
	}

	for (group = 0; group < G_2G_N; group++) {
		if (dpk_info->dpk_2g_result[path][group] == 0x0) {
			is_2g_fail = true;
			break;
		}
	}

	for (group = G_2G_N; group < DPK_GROUP_NUM_8195B; group++) {
		if (dpk_info->dpk_5g_result[path][group - G_2G_N] == 0x0) {
			is_5g_fail = true;
			break;
		}
	}
	if (!(is_2g_fail || is_5g_fail))
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);
	if (dpk_info->dpk_path_ok > 0)
		dpk_info->is_dpk_enable = 1;
}

void _dpk_path_select_8195b(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

#if (DPK_DO_PATH_A)
	_dpk_calibrate_8195b(dm, RF_PATH_A);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_A)) >> RF_PATH_A)
		_dpk_on_8195b(dm, RF_PATH_A);
#endif
}

void _dpk_thermal_read_8195b(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x3);
	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x0);
	odm_set_rf_reg(dm, path, 0x42, BIT(17) | BIT(16), 0x3);
	ODM_delay_us(10);

	dpk_info->thermal_dpk[path] = (u8)odm_get_rf_reg(dm, (enum rf_path)path,
							 RF_0x42, 0x0FC00);
	RF_DBG(dm, DBG_RF_DPK, "[DPK] curr thermal S%d = %d\n", path,
	       dpk_info->thermal_dpk[path]);
}

u32 _dpk_pas_get_iq_8195b(struct dm_struct *dm, u8 gs_type)
{
	s32 i_val = 0, q_val = 0;

	//RF_DBG(dm, DBG_RF_DPK, "\n");
	odm_set_bb_reg(dm, R_0x1bcc, BIT(26), 0x0);

	if (gs_type == GSK3) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_PAS_Gain_1st_8195b\n");
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e03f);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00090000);
	} else if (gs_type == GSK2) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_PAS_Gain_8rd_8195b\n");
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e03e);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00060000);
	} else if (gs_type == GSK1) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]_dpk_PAS_Loss_read_8195b\n");
		odm_set_bb_reg(dm, R_0x1b90, MASKDWORD, 0x0105e038);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00060000);
	}
	i_val = odm_get_bb_reg(dm, R_0x1bfc, MASKHWORD);
	q_val = odm_get_bb_reg(dm, R_0x1bfc, MASKLWORD);

	if (i_val >> 15 != 0)
		i_val = 0x10000 - i_val;
	if (q_val >> 15 != 0)
		q_val = 0x10000 - q_val;
#if 1
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%x] i=0x%x, q=0x%x, i^2+q^2=0x%x\n",
	       gs_type, i_val, q_val, i_val * i_val + q_val * q_val);
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%x] i=%d, q=%d, i^2+q^2=%d\n",
	       gs_type, i_val, q_val, i_val * i_val + q_val * q_val);

#endif
	return i_val * i_val + q_val * q_val;
}

s32 _dpk_pas_iq_check_8195b(struct dm_struct *dm, u8 path, u8 gs)
{
	u8 result = 0;
	u32 i_val = 0, q_val = 0, loss = 0, gain = 0;
	s32 loss_db = 0;
	s32 gain_db = 0;
	s32 gain_db2 = 0;

	gain = _dpk_pas_get_iq_8195b(dm, gs);
	gain_db =  (s32)(3 * (halrf_psd_log2base(gain) / 10 - 200));
	gain_db2 = halrf_psd_log2base(gain);
#if 1
	RF_DBG(dm, DBG_RF_DPK, "[DPK]i^2+q^2 = %d\n", gain);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]log(gain) = %d\n", gain_db2);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]Gain_db = %d\n", gain_db);
#endif
	return gain_db;
}

boolean _dpk_pas_LBTAA_8195b(struct dm_struct *dm, u8 path, u8 gs_type)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 attenu;
	s32 gain_db;
	u32 rf63, rf57;
	boolean fail = true;

//step2
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	rf63 = odm_get_rf_reg(dm, (enum rf_path)path, 0x63, 0xfffff);
	rf57 = odm_get_rf_reg(dm, (enum rf_path)path, 0x57, 0xfffff);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]start rf63 = 0x%x\n", rf63);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]start rf57 = 0x%x\n", rf57);

	if (*dm->band_type == ODM_BAND_2_4G)
		attenu = (u8)odm_get_rf_reg(dm, path, 0x57, 0x0070);
	else
		attenu = (u8)odm_get_rf_reg(dm, path, 0x63, 0xf000);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK]start attenu = 0x%x\n", attenu);

	if (gs_type == GSK3) {
		gain_db = _dpk_pas_iq_check_8195b(dm, path, GSK3);
		if (gain_db > -20) {
			attenu = attenu + 2;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] Case 6\n");
		} else {
			fail = false;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK3] Case 7\n");
		}
	}

	if (gs_type == GSK2) {
		gain_db = _dpk_pas_iq_check_8195b(dm, path, GSK2);
		if (gain_db > -20) {
			attenu = attenu + 2;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK2] Case 4\n");
		} else {
			fail = false;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK2] Case 5\n");
		}
	}
//step3
	if (gs_type == GSK1) {
		gain_db = _dpk_pas_iq_check_8195b(dm, path, GSK1);
		if (gain_db < -80) {
			attenu = attenu - 2;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 1\n");
		} else if (gain_db > -20) {
			attenu = attenu + 2;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 2\n");
		} else {
			fail = false;
			RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK1] Case 3\n");
		}
	}
#if 1
	if (*dm->band_type == ODM_BAND_2_4G)
		odm_set_rf_reg(dm, path, 0x57, 0x0070, attenu);
	else
		odm_set_rf_reg(dm, path, 0x63, 0xf000, attenu);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][GSK]end attenu = 0x%x\n", attenu);
#endif
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	rf63 = odm_get_rf_reg(dm, (enum rf_path)path, 0x63, 0xfffff);
	rf57 = odm_get_rf_reg(dm, (enum rf_path)path, 0x57, 0xfffff);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]end rf63 = 0x%x\n", rf63);
	RF_DBG(dm, DBG_RF_DPK, "[DPK]end rf57 = 0x%x\n", rf57);
	return fail;
}

boolean _dpk_pas_agc_8195b(struct dm_struct *dm, u8 path, u8 gs)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u32 rf63;
	boolean fail = true, kfail = true;
	u32 i;

	RF_DBG(dm, DBG_RF_DPK, "\n");
	RF_DBG(dm, DBG_RF_DPK, "[DPK]== GS DPK GainSearch ==\n");
	odm_write_4byte(dm, 0x1b00, 0x00000008 | path << 1);
	odm_write_1byte(dm, R_0x1b92, 0x05);
	odm_write_4byte(dm, 0x1b98, 0x41382e21);
	odm_write_1byte(dm, 0x1b8d, 0x40);

	kfail = _dpk_one_shot_8195b(dm, path, GAIN_LOSS);

	if (DPK_PAS_DBG_8195B)
		_dpk_pas_read_8195b(dm, true, path);

	fail = _dpk_pas_LBTAA_8195b(dm, path, gs);

	return fail;
}

void dpk_result_summary_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path, group;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ======== DPK Result Summary =======\n");

	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		for (group = 0; group < G_2G_N; group++) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK]S%d[%d]2Gpwsf= 0x%x, dpk_result[%x]= %d\n",
			       path, group, dpk_info->pwsf_2g[path][group],
			       group, dpk_info->dpk_2g_result[path][group]);
		}
		for (group = G_2G_N; group < DPK_GROUP_NUM_8195B; group++) {
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

#if (DPK_SRAM_read_DBG_8198F)
	dpk_sram_read_8195b(dm);
#endif
}

void dpk_reload_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path;

	_dpk_lut_sram_write_8195b(dm);

	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | (path << 1));

		if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK reload Pass\n");
			_dpk_on_8195b(dm, path);
		} else {
			odm_set_bb_reg(dm, R_0x1b20, 0x07000000, 0x7);
			RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK reload fail\n");
		}
	}
	dpk_enable_disable_8195b(dm);
}

boolean _do_dpk_8195b(void *dm_void, boolean do_widebandtxk)
{
	u32 mac_reg_backup[DPK_MAC_REG_NUM_8195B];
	u32 bb_reg_backup[DPK_BB_REG_NUM_8195B];
	u32 rf_reg_backup[DPK_RF_REG_NUM_8195B][DPK_RF_PATH_NUM_8195B];
	u32 mac_reg[DPK_MAC_REG_NUM_8195B] = {0x520, 0x550, 0x1518};
	u32 bb_reg[DPK_BB_REG_NUM_8195B] = {0x808, 0x90c, 0xc00, 0xcb0,
							0xcb4, 0xcbc, 0x1990,
							0x9a4, 0xa04, 0xc58,
							0xc5c, 0xe58, 0xe5c,
							0xc6c, 0xe6c, 0x90c,
							0x1904, 0xcb0, 0x90c,
							0xcb4, 0xcbc, 0xc00,
							0x1b2c, 0x1b38, 0x1b3c,
							0x810, 0xc68};
	u32 rf_reg[DPK_RF_REG_NUM_8195B] = {0x57, 0x63, 0x8c, 0xdf,
							0xde, 0x8f, 0x0, 0x1};
	u8 path = 0x0, retry_cnt = 0, tx_agc_search, k;
	u16 i;
	boolean returnflag = false, dpk_fail = true, dpk_txk_fail = true;
	boolean gs_fail = false;
	static boolean do_clear = true;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	k = dpk_channel_transfer_8195b(dm);

	_backup_mac_bb_registers_8195b(dm, mac_reg, mac_reg_backup,
				       DPK_MAC_REG_NUM_8195B);
	_backup_mac_bb_registers_8195b(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8195B);
	_backup_rf_registers_8195b(dm, rf_reg, rf_reg_backup);

	_dpk_mac_bb_setting_8195b(dm);

	_dpk_manual_txagc_8195b(dm, true);

	if (do_widebandtxk) {
		_iqk_init_8195b(dm);
		_iqk_afe_setting_8195b(dm, true);
		// TXK
		_dpk_txk_setting_8195b(dm, RF_PATH_A);
		dpk_txk_fail = _dpk_one_shot_8195b(dm, RF_PATH_A, DPK_TXK);
		//ODM_delay_ms(50);
		//restore rf debug mode
		odm_set_rf_reg(dm, path, 0xde, BIT(16), 0x0);
		odm_set_rf_reg(dm, path, 0xee, BIT(18), 0x0);
	}

	_dpk_init_phy_8195b(dm);

	_dpk_afe_setting_8195b(dm, true);

	_dpk_rfsetting_8195b(dm, *dm->band_type);

	_dpk_thermal_read_8195b(dm, RF_PATH_A);
#if 0
	if (k == 3)
		ODM_delay_ms(5);
#endif

	//GS Start
	for (i = GSK3; i >= GSK1; i--)
		gs_fail = _dpk_pas_agc_8195b(dm, path, i);

	//DPK start
	RF_DBG(dm, DBG_RF_DPK, "[DPK] _dpk_gainloss_8195b V2 !!!\n");

	tx_agc_search = _dpk_gainloss_8195b(dm, path);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] _dpk_by_path_8195b !!!\n");

	dpk_fail = _dpk_by_path_8195b(dm, tx_agc_search, path, 0);

	_dpk_on_8195b(dm, path);

	_dpk_check_fail_8195b(dm, dpk_fail, path, k);

	dpk_info->dpk_path_ok = 0x1;

	dpk_info->is_dpk_enable = 0x1;

	_dpk_afe_setting_8195b(dm, false);

	_dpk_manual_txagc_8195b(dm, false);

	_reload_rf_registers_8195b(dm, rf_reg, rf_reg_backup);
	_reload_mac_bb_registers_8195b(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8195B);
	_reload_mac_bb_registers_8195b(dm, mac_reg, mac_reg_backup,
				       DPK_MAC_REG_NUM_8195B);
	return true;
}

void do_dpk_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	boolean dpk_done = true;
	boolean ret_flag = false;

	if (dm->ext_pa && (*dm->band_type == ODM_BAND_2_4G)) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]Skip DPK due to ext_PA exist!!\n");
		ret_flag = true;
	} else if (dm->ext_pa_5g && (*dm->band_type == ODM_BAND_5G)) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Skip DPK due to 5G_ext_PA exist!!\n");
		ret_flag = true;
	} else if (!dpk_info->is_dpk_pwr_on) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]Skip DPK due to DPD PWR off !!\n");
		ret_flag = true;
	} else {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK]***DPK Start (Ver: %s), Cv: %d, Package: %d***\n",
		       DPK_VER_8195B, dm->cut_version, dm->package_type);
		ret_flag = false;
	}
	if (!ret_flag) {
		if (!dpk_get_dpkbychannel_8195b(dm)) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK] do_dpk by group\n");
			dpk_by_group_8195b(dm); /*do dpk 9 ch*/
			dpk_result_summary_8195b(dm);
		} else {
			RF_DBG(dm, DBG_RF_DPK, "[DPK]do_dpk by channel\n");
			dpk_done = _do_dpk_8195b(dm, false);
		}
	}
}

void dpk_enable_disable_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path;

	for (path = 0; path < DPK_RF_PATH_NUM_8195B; path++) {
		if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
			odm_set_bb_reg(dm, R_0x1b00, MASKDWORD,
				       0x8 | (path << 1));

			if (dpk_info->is_dpk_enable) {
				odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x0);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] S%d DPK enable !!!\n", path);
			} else {
				odm_set_bb_reg(dm, R_0x1b20, BIT(25), 0x1);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK] S%d DPK bypass !!!\n", path);
			}
		}
	}
}

void dpk_by_group_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	boolean dpk_done = true;

	// 2.4G band
	*dm->band_type = ODM_BAND_2_4G;
	*dm->band_width = CHANNEL_WIDTH_20;
	config_phydm_switch_band_8195b(dm, 3);
	// 20M bandwidth
	config_phydm_switch_bandwidth_8195b(dm, 0x1, CHANNEL_WIDTH_20);
	// channel 3 G0
	config_phydm_switch_channel_8195b(dm, 3);
	*dm->channel = 3;
	dpk_done = _do_dpk_8195b(dm, FALSE);
	// channel 5 G1
	config_phydm_switch_channel_8195b(dm, 5);
	*dm->channel = 5;
	dpk_done = _do_dpk_8195b(dm, FALSE);
	// channel 11 G2
	config_phydm_switch_channel_8195b(dm, 11);
	*dm->channel = 11;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// 5G band
	*dm->band_type = ODM_BAND_5G;
	*dm->band_width = CHANNEL_WIDTH_20;
	config_phydm_switch_band_8195b(dm, 40);
	// channel 40 G3
	config_phydm_switch_channel_8195b(dm, 40);
	*dm->channel = 40;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 100 G4
	config_phydm_switch_channel_8195b(dm, 100);
	*dm->channel = 100;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 120 G5
	config_phydm_switch_channel_8195b(dm, 120);
	*dm->channel = 120;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 149 G6
	config_phydm_switch_channel_8195b(dm, 149);
	*dm->channel = 149;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 169 G7
	config_phydm_switch_channel_8195b(dm, 169);
	*dm->channel = 169;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 177 G8
	config_phydm_switch_channel_8195b(dm, 177);
	*dm->channel = 177;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// 80M bandwidth
	*dm->band_type = ODM_BAND_5G;
	*dm->band_width = CHANNEL_WIDTH_80;
	config_phydm_switch_bandwidth_8195b(dm, 0x1, CHANNEL_WIDTH_80);

	// channel 42 G9
	config_phydm_switch_channel_8195b(dm, 42);
	*dm->channel = 42;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 58 G10
	config_phydm_switch_channel_8195b(dm, 58);
	*dm->channel = 58;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 106 G11
	config_phydm_switch_channel_8195b(dm, 106);
	*dm->channel = 106;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 122 G12
	config_phydm_switch_channel_8195b(dm, 122);
	*dm->channel = 122;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 138 G13
	config_phydm_switch_channel_8195b(dm, 138);
	*dm->channel = 138;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 155 G14
	config_phydm_switch_channel_8195b(dm, 155);
	*dm->channel = 155;
	dpk_done = _do_dpk_8195b(dm, FALSE);

	// channel 171 G15
	config_phydm_switch_channel_8195b(dm, 171);
	*dm->channel = 171;
	dpk_done = _do_dpk_8195b(dm, FALSE);
}

void dpk_track_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	//struct rtl8192cd_priv *priv = dm->priv;

	s8 pwsf_a, pwsf_b, pwsf_c, pwsf_d;
	u8 is_increase, i = 0, k = 0;
	u8 thermal_dpk_avg_count = 0;
	u8 delta_dpk[4] = {0, 0, 0, 0};
	u8 offset[4] = {0, 0, 0, 0};
	u32 thermal_dpk_avg[4] = {0, 0, 0, 0};
	u8 thermal_value[4] = {0, 0, 0, 0};
	u8 path, pwsf[4] = {0, 0, 0, 0};
	s8 idx_offset[4] = {0, 0, 0, 0};
	u8 avg_times = 0x4;

	if (!dpk_info->is_dpk_by_channel)
		dpk_info->thermal_dpk[0] = rf->eeprom_thermal;

	/* calculate average thermal meter */
	/*thermal meter trigger*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17) | BIT(16), 0x3);
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17) | BIT(16), 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0x42, BIT(17) | BIT(16), 0x3);

	ODM_delay_us(10);
	/*get thermal meter*/
	thermal_value[0] = (u8)odm_get_rf_reg(dm, RF_PATH_A, 0x42, 0xfc00);

	dpk_info->thermal_dpk_avg[0][dpk_info->thermal_dpk_avg_index] =
		thermal_value[0];
	dpk_info->thermal_dpk_avg_index++;

	/*Average times */
	if (dpk_info->thermal_dpk_avg_index == THERMAL_DPK_AVG_NUM)
		dpk_info->thermal_dpk_avg_index = 0;

	for (i = 0; i < avg_times; i++) {
		if (dpk_info->thermal_dpk_avg[0][i]) {
			thermal_dpk_avg[0] += dpk_info->thermal_dpk_avg[0][i];
			thermal_dpk_avg_count++;
		}
	}

	/*Calculate Average ThermalValue after average enough times*/
	if (thermal_dpk_avg_count) {
		thermal_value[0] = (thermal_dpk_avg[0] / thermal_dpk_avg_count);
		thermal_value[0] = (u8)thermal_value[0];
		RF_DBG(dm, DBG_RF_DPK | DBG_RF_TX_PWR_TRACK,
		       "[DPK_track] S0 AVG (PG) Thermal Meter = %d (%d)\n",
		       thermal_value[0], dpk_info->thermal_dpk[0]);
	}

	delta_dpk[0] = HALRF_ABS(thermal_value[0], dpk_info->thermal_dpk[0]);

	is_increase = ((thermal_value[0] < dpk_info->thermal_dpk[0]) ? 0 : 1);

	offset[0] = delta_dpk[0] / DPK_THRESHOLD_8195B;

	k = dpk_channel_transfer_8195b(dm);

	if (*dm->band_type == ODM_BAND_2_4G)
		pwsf_a = dpk_info->pwsf_2g[0][k];
	else
		pwsf_a = dpk_info->pwsf_5g[0][k - G_2G_N];

	if (is_increase) {
		if ((pwsf_a + offset[0]) > 0x1f)
			pwsf_a = offset[0] - (0x20 - pwsf_a);
		else
			pwsf_a = pwsf_a + offset[0];
	} else {
		if (offset[0] > pwsf_a)
			pwsf_a = 0x1f - offset[0] + pwsf_a + 1;
		else
			pwsf_a = pwsf_a - offset[0];
	}

	odm_write_1byte(dm, 0x1b00, 0x8);
	odm_set_bb_reg(dm, R_0x1bd0, 0x00001f00, pwsf_a);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_a after tracking is %d (0x%x),0x1bd0=0x%x\n",
	       pwsf_a, (pwsf_a & 0x1f),
	       odm_get_bb_reg(dm, R_0x1bd0, MASKDWORD));
}

void dpk_set_dpkbychannel_8195b(void *dm_void, boolean dpk_by_ch)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_by_channel = dpk_by_ch;
}

boolean dpk_get_dpkbychannel_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	return dpk_info->is_dpk_by_channel;
}

void dpk_set_is_dpk_enable_8195b(void *dm_void, boolean is_dpk_enable)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_enable = is_dpk_enable;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] set_is_dpk_enable_8195b\n");
}

boolean dpk_get_is_dpk_enable_8195b(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] get_is_dpk_enable_8195b= %x\n",
	       dpk_info->is_dpk_enable);

	return dpk_info->is_dpk_enable;
}
#endif
