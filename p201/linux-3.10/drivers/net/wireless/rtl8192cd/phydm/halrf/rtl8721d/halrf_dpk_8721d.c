// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018  Realtek Corporation.
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

#if (RTL8721D_SUPPORT == 1)

/*8721D DPK v02 20190325 by shirley*/

u32 _dpk_log2base(u32 val)
{
	u8 j;
	u32 tmp, tmp2, val_integerd_b = 0, tindex, shiftcount = 0;
	u32 result, val_fractiond_b = 0;
	u32 table_fraction[21] = {0, 432, 332, 274, 232, 200, 174,
				  151, 132, 115, 100, 86, 74, 62,
				  51, 42, 32, 23, 15, 7, 0};

	if (val == 0)
		return 0;

	tmp = val;

	while (1) {
		if (tmp == 1)
			break;

		tmp = (tmp >> 1);
		shiftcount++;
	}

	val_integerd_b = shiftcount + 1;

	tmp2 = 1;
	for (j = 1; j <= val_integerd_b; j++)
		tmp2 = tmp2 * 2;

	tmp = (val * 100) / tmp2;/*keep two decimal point*/
	tindex = tmp / 5;

	if (tindex > 20)
		tindex = 20;

	val_fractiond_b = table_fraction[tindex];

	result = val_integerd_b * 100 - val_fractiond_b;

	return result;
}

void _backup_mac_bb_registers_8721d(struct dm_struct *dm,
				    u32 *reg,
				    u32 *reg_backup,
				    u32 reg_num)
{
	u32 i;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup MAC/BB parameters !\n");
	for (i = 0; i < reg_num; i++) {
		reg_backup[i] = odm_read_4byte(dm, reg[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _backup_rf_registers_8721d(struct dm_struct *dm,
				u32 *rf_reg,
				u32 rf_reg_backup[][DPK_RF_PATH_NUM_8721D])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8721D; i++) {
		rf_reg_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A,
							     rf_reg[i],
							     RFREG_MASK);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Backup RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
#endif
	}
}

void _reload_mac_bb_registers_8721d(struct dm_struct *dm,	u32 *reg,
				    u32 *reg_backup, u32 reg_num)
{
	u32 i;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload ADDA power saving parameters !\n");
	for (i = 0; i < reg_num; i++) {
		odm_write_4byte(dm, reg[i], reg_backup[i]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload 0x%x = 0x%x\n",
		       reg[i], reg_backup[i]);
#endif
	}
}

void _reload_rf_registers_8721d(struct dm_struct *dm,	u32 *rf_reg,
				u32 rf_reg_backup[][DPK_RF_PATH_NUM_8721D])
{
	u32 i;

	for (i = 0; i < DPK_RF_REG_NUM_8721D; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_A]);
#if 0
		RF_DBG(dm, DBG_RF_DPK, "[DPK] Reload RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
#endif
	}
}

void phy_dpk_init_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_DPK, "[DPK]  ======== phy dpk init 8721d =======\n");
	odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x0005e018);
	odm_set_bb_reg(dm, R_0xb04, MASKDWORD, 0xf76d9f84);
	odm_set_bb_reg(dm, R_0xb28, MASKDWORD, 0x000844aa);
	odm_set_bb_reg(dm, R_0xb68, MASKDWORD, 0x11120200);
	/* pwsf boundary */
	odm_set_bb_reg(dm, R_0xb30, 0x000fffff, 0x0007bdef);
	/* LUT SRAM block selection */
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x40000000);
	odm_set_bb_reg(dm, R_0xbc0, MASKDWORD, 0x0000a9bf);
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
	/*tx_ramp*/
	odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x41382e21);
	odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x5b554f48);
	odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x6f6b6661);
	odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x817d7874);
	odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x908c8884);
	odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x9d9a9793);
	odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0xaaa7a4a1);
	odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0xb6b3b0ad);

	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x40000000);
	/* ramp_inverse */
	odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x02ce03e8);
	odm_set_bb_reg(dm, R_0xb04, MASKDWORD, 0x01fd024c);
	odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x01a101c9);
	odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x016a0183);
	odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x01430153);
	odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x01280134);
	odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x0112011c);
	odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x01000107);
	odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0x00f200f9);
	odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0x00e500eb);
	odm_set_bb_reg(dm, R_0xb28, MASKDWORD, 0x00da00e0);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00d200d6);
	odm_set_bb_reg(dm, R_0xb30, MASKDWORD, 0x00c900cd);
	odm_set_bb_reg(dm, R_0xb34, MASKDWORD, 0x00c200c5);
	odm_set_bb_reg(dm, R_0xb38, MASKDWORD, 0x00bb00be);
	odm_set_bb_reg(dm, R_0xb3c, MASKDWORD, 0x00b500b8);

	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0xb38, 0x0c000000, 0x3);
	/*pwsf offset table*/
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x40000304);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x41000203);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x42000102);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x43000101);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x44000101);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x45000101);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x46000101);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x47000101);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4800caff);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x490080a1);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4A005165);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4B003340);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4C002028);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4D001419);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4E000810);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x4F000506);

	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0xb38, 0x0c000000, 0x3);
	/*write even LUT*/
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x01500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x02500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x03500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x04500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x05500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x06500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x07500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x08500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x09500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0A500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0B500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0C500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0D500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0E500000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0F500000);
	/*write odd LUT*/
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x01900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x02900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x03900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x04900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x05900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x06900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x07900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x08900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x09900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0A900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0B900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0C900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0D900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0E900000);
	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x0F900000);

	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);
	/*IQK Setting*/
	/*IQK new location:0xe20[9:0]=tx_y_manual, 0xe20[19:10]=rx_y_manual*/
	odm_set_bb_reg(dm, R_0xe20, MASKDWORD, 0xc0000000);
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x40000000);
	odm_set_bb_reg(dm, R_0xb40, MASKDWORD, 0x00040100);
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0xe30, MASKDWORD, 0x1000cc1b);
	odm_set_bb_reg(dm, R_0xe34, MASKDWORD, 0x1000cc1b);
	odm_set_bb_reg(dm, R_0xe38, MASKDWORD, 0x821403ff);
	odm_set_bb_reg(dm, R_0xe3c, MASKDWORD, 0x00160000);
	odm_set_bb_reg(dm, R_0xe40, MASKDWORD, 0x01007c00);
	odm_set_bb_reg(dm, R_0xe44, MASKDWORD, 0x01004800);
	odm_set_bb_reg(dm, R_0xe48, MASKDWORD, 0xf8000800);
	odm_set_bb_reg(dm, R_0xe4c, MASKDWORD, 0x00002911);
}

void _dpk_mac_bb_setting_8721d(struct dm_struct *dm)
{
	/*BB AFE on*/
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05601);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000800e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25204000);
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccf000c0);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0x800, BIT(24), 0x0); /*disable CCK block*/

	/*set CCA TH to highest*/
	odm_set_bb_reg(dm, R_0x954, 0xF0000000, 0xf);
	odm_set_bb_reg(dm, R_0x958, 0x000F0000, 0xf);
	odm_set_bb_reg(dm, R_0xc3c, 0x000001F8, 0x77);
	odm_set_bb_reg(dm, R_0xc30, 0x0000000f, 0xf);
	odm_set_bb_reg(dm, R_0xc84, 0xf0000000, 0xf);
}

void _dpk_tx_ramp_setting_8721d(struct dm_struct *dm, u8 ramp_type)
{
	switch (ramp_type) {
	case TX_FULL_RAMP:
		odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x41382e21);
		odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x5b554f48);
		odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x6f6b6661);
		odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x817d7874);
		odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x908c8884);
		odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x9d9a9793);
		odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0xaaa7a4a1);
		odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0xb6b3b0ad);
		break;
	case GAINLOSS_RAMP:
		/*0,3,(4),5,7,9,12,15,19,24,31*/
		odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x41000021);
		odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x5b004f00);
		odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x00006600);
		odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x81000074);
		odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x90000000);
		odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0x000000a1);
		odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0xb6000000);
		break;
	case TX_PULSE_RAMP:
		odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x00380021);
		odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x00550048);
		odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x006b0061);
		odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x007d0074);
		odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x008c0084);
		odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x009a0093);
		odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0x00a700a1);
		odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0x00b300ad);
		break;
	case TX_INVERSE:
		/*tx inverse*/
		odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x40000000);
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x02ce03e8);
		odm_set_bb_reg(dm, R_0xb04, MASKDWORD, 0x01fd024c);
		odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x01a101c9);
		odm_set_bb_reg(dm, R_0xb0c, MASKDWORD, 0x016a0183);
		odm_set_bb_reg(dm, R_0xb10, MASKDWORD, 0x01430153);
		odm_set_bb_reg(dm, R_0xb14, MASKDWORD, 0x01280134);
		odm_set_bb_reg(dm, R_0xb18, MASKDWORD, 0x0112011c);
		odm_set_bb_reg(dm, R_0xb1c, MASKDWORD, 0x01000107);
		odm_set_bb_reg(dm, R_0xb20, MASKDWORD, 0x00f200f9);
		odm_set_bb_reg(dm, R_0xb24, MASKDWORD, 0x00e500eb);
		odm_set_bb_reg(dm, R_0xb28, MASKDWORD, 0x00da00e0);
		odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00d200d6);
		odm_set_bb_reg(dm, R_0xb30, MASKDWORD, 0x00c900cd);
		odm_set_bb_reg(dm, R_0xb34, MASKDWORD, 0x00c200c5);
		odm_set_bb_reg(dm, R_0xb38, MASKDWORD, 0x00bb00be);
		odm_set_bb_reg(dm, R_0xb3c, MASKDWORD, 0x00b500b8);
		odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
		break;
	default:
		break;
	}
}
void _dpk_one_shot_8721d(struct dm_struct *dm,	u8 action)
{
	u8 dpk_cmd = 0x0;

	dpk_cmd = (action - 1) * 0x40;

	odm_write_1byte(dm, R_0xb2b, dpk_cmd + 0x80);
	odm_write_1byte(dm, R_0xb2b, dpk_cmd);
#if 0
	RF_DBG(dm, DBG_RF_DPK, "[DPK][one-shot] reg=0x%x, dpk_cmd=0x%x\n",
	       temp_reg, dpk_cmd);
#endif
	ODM_delay_ms(5);
}

void _dpk_thermal_read_8721d(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	odm_set_rf_reg(dm, path, RF_0x42, (BIT(12) | BIT(11)), 0x03);
	ODM_delay_us(5);

	dpk_info->thermal_dpk[path] = (u8)odm_get_rf_reg(dm,
							 path, RF_0x42, 0x7e0);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] thermal S%d = %d\n", path,
	       dpk_info->thermal_dpk[path]);
}

u32 _dpk_pas_get_iq_8721d(struct dm_struct *dm,	boolean is_gain_chk)
{
	/*get PAscan result*/
	s32 i_val = 0, q_val = 0;
	u32 reg_b68;

	reg_b68 = odm_get_bb_reg(dm, R_0xb68, MASKDWORD);
	odm_set_bb_reg(dm, R_0xb68, BIT(26), 0x0);

	if (is_gain_chk) {
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x0101f03f); /*gain*/
		i_val = odm_get_bb_reg(dm, R_0xbe8, MASKHWORD);
		q_val = odm_get_bb_reg(dm, R_0xbe8, MASKLWORD);
	} else {
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x0101f038); /*loss*/
		i_val = odm_get_bb_reg(dm, R_0xbdc, MASKHWORD);
		q_val = odm_get_bb_reg(dm, R_0xbdc, MASKLWORD);
	}
	odm_set_bb_reg(dm, R_0xb68, MASKDWORD, reg_b68);

	/*i/q val=(s,16.10)*/
	if (i_val >> 15 != 0)
		i_val = 0x10000 - i_val;
	if (q_val >> 15 != 0)
		q_val = 0x10000 - q_val;

#if (DPK_GAINLOSS_DBG_8721D)
	RF_DBG(dm, DBG_RF_DPK, "[DPK][%s] i=0x%x, q=0x%x, i^2+q^2=0x%x\n",
	       is_gain_chk ? "Gain" : "Loss",
	       i_val, q_val, i_val * i_val + q_val * q_val);
#endif
	return i_val * i_val + q_val * q_val; /*gain*/
}

u8 _dpk_pas_iq_check_8721d(struct dm_struct *dm,	u8 limited_pga)
{
	u8 result = 0;
	u32 loss = 0, gain = 0;
	s32 loss_db = 0, gain_db = 0;

	loss = _dpk_pas_get_iq_8721d(dm, LOSS_CHK);
	gain = _dpk_pas_get_iq_8721d(dm, GAIN_CHK);
	/*gain = dec2hec((10^(xdb/20)*1024)^2); 0db = 0x100000*/
	loss_db = 3 * _dpk_log2base(loss);
	gain_db = 3 * _dpk_log2base(gain);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Gain = 0x%x = %ddb, Loss = 0x%x = %ddb\n",
	       gain, gain_db, loss, loss_db);

#if (DPK_GAINLOSS_DBG_8721D)
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK][GL_Chk] G=%d.%02d, L=%d.%02d, GL=%d.%02ddB\n",
		(gain_db - 6020) / 100, HALRF_ABS(6020, gain_db) % 100,
		(loss_db - 6020) / 100, HALRF_ABS(6020, loss_db) % 100,
		(gain_db - loss_db) / 100, (gain_db - loss_db) % 100);
#endif

	if (gain == 0 && loss == 0) {
		printf("[DPK] <============= WARNNING===============>\n");
		printf("[DPK] <========CHECK INITIAL STATUS!!=======>\n");
		printf("[DPK] <============= WARNNING===============>\n");
		result = 0xff;
		return result;
	}
	if (gain > 0xB53BE && !limited_pga) {
		/*Gain > -1.5dB happen*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] Gain > -1.5dB happen!\n");
		result = 1;
		return result;
	} else if ((gain < 0x2892c) && !limited_pga) {
		/*Gain < -8dB happen*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] Gain < -8dB happen!!\n");
		result = 2;
		return result;
	} else if ((gain_db - loss_db) > 600) {
		/*GL > 6dB*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] GL > 6dB happen!!\n");
		result = 3;
		return result;
	} else if ((gain_db - loss_db) < 200) {
		/*GL < 2dB*/
		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL_Chk] GL < 2dB happen!!\n");
		result = 4;
		return result;
	} else {
		return result;
	}
}

void _dpk_pas_read_8721d(struct dm_struct *dm,	boolean is_gainloss)
{
	int k;
	u32 reg_b00, reg_b68, reg_bdc, reg_be0, reg_be4, reg_be8;

	reg_b00 = odm_get_bb_reg(dm, R_0xb00, MASKDWORD);
	reg_b68 = odm_get_bb_reg(dm, R_0xb68, MASKDWORD);

	if (is_gainloss)
		odm_set_bb_reg(dm, R_0xb68, BIT(26), 0x0);

	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, (0x0101f038 | k));
		reg_bdc = odm_get_bb_reg(dm, R_0xbdc, MASKDWORD);
		reg_be0 = odm_get_bb_reg(dm, R_0xbe0, MASKDWORD);
		reg_be4 = odm_get_bb_reg(dm, R_0xbe4, MASKDWORD);
		reg_be8 = odm_get_bb_reg(dm, R_0xbe8, MASKDWORD);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] PA scan S0[%d] = 0x%x\n", k,
		       reg_bdc);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] PA scan S0[%d] = 0x%x\n", k,
		       reg_be0);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] PA scan S0[%d] = 0x%x\n", k,
		       reg_be4);
		RF_DBG(dm, DBG_RF_DPK, "[DPK] PA scan S0[%d] = 0x%x\n", k,
		       reg_be8);
	}

	odm_set_bb_reg(dm, R_0xb00, MASKDWORD, reg_b00);
	odm_set_bb_reg(dm, R_0xb68, MASKDWORD, reg_b68);
}

boolean _dpk_pas_agc_8721d(struct dm_struct *dm, u8 path)
{
	u8 tmp_txagc, tmp_pga, i = 0;
	u8 goout = 0, limited_pga = 0;

	do {
		switch (i) {
		case 0: /*one-shot*/
			tmp_txagc = odm_get_rf_reg(dm, (enum rf_path)path,
						   RF_0x00, 0x0001f);
			tmp_pga = odm_get_rf_reg(dm, (enum rf_path)path,
						 RF_0x8f, 0x00006000);

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK][AGC] TXAGC=0x%x, PGA=0x%x\n",
			       tmp_txagc, tmp_pga);

			if (!limited_pga)
				_dpk_one_shot_8721d(dm, GAIN_LOSS);

			if (DPK_PAS_DBG_8721D)
				_dpk_pas_read_8721d(dm, TRUE);

			i = _dpk_pas_iq_check_8721d(dm, limited_pga);
			if (i == 0xff)
				return 0;
			if (i == 0)
				goout = 1;
			break;

		case 1: /*Gain > criterion*/
			if (tmp_pga == 0x3) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x00006000, 0x1);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA(-1) = 1\n");
			} else if (tmp_pga == 0x1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x00006000, 0x0);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA(-1) = 0\n");
			} else if (tmp_pga == 0x0 || tmp_pga == 0x2) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA@ lower bound!!\n");
				limited_pga = 1;
			}
			i = 0;
			break;

		case 2: /*Gain < criterion*/
			if (tmp_pga == 0x0 || tmp_pga == 0x2) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x00006000, 0x1);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA(+1) = 1\n");
			} else if (tmp_pga == 0x1) {
				odm_set_rf_reg(dm, (enum rf_path)path,
					       RF_0x8f, 0x00006000, 0x3);
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA(+1) = 3\n");
			} else if (tmp_pga == 0x3) {
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] PGA@ upper bound!!\n");
				limited_pga = 1;
			}
			i = 0;
			break;

		case 3: /*GL > criterion*/
			if (tmp_txagc == 0x0) {
				goout = 1;
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] TXAGC@ lower bound!!\n");
				break;
			}
			tmp_txagc--;
			odm_set_rf_reg(dm, (enum rf_path)path,
				       RF_0x00, 0x0001f, tmp_txagc);
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] txagc(-1) = 0x%x\n",
			       tmp_txagc);
			limited_pga = 0;
			i = 0;
			ODM_delay_ms(1);
			break;

		case 4:	/*GL < criterion*/
			if (tmp_txagc == 0x1f) {
				goout = 1;
				RF_DBG(dm, DBG_RF_DPK,
				       "[DPK][AGC] TXAGC@ upper bound!!\n");
				break;
			}
			tmp_txagc++;
			odm_set_rf_reg(dm, (enum rf_path)path,
				       RF_0x00, 0x0001f, tmp_txagc);
			RF_DBG(dm, DBG_RF_DPK, "[DPK][AGC] txagc(+1) = 0x%x\n",
			       tmp_txagc);
			limited_pga = 0;
			i = 0;
			ODM_delay_ms(1);
			break;

		default:
			goout = 1;
			break;
		}
	} while (!goout);
	return 1;
}

void _dpk_pas_interpolation_8721d(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 k, j;
	u32 pas_data;

	odm_set_bb_reg(dm, R_0xb68, BIT(26), 0x0);

	for (k = 0; k < 8; k++) {
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, (0x0105f038 | k));
		for (j = 0; j < 4; j++) {
			pas_data = odm_get_bb_reg(dm, R_0xbdc + 0x4 * j, MASKDWORD);
			dpk_info->tmp_pas_i[k * 4 + j] = (pas_data >> 16) & 0xffff;
			dpk_info->tmp_pas_q[k * 4 + j] = pas_data & 0xffff;

			if (DPK_PULSE_DBG_8721D)
				RF_DBG(dm, DBG_RF_DPK, "[DPK] Pulse PAS[%02d] = 0x%08x\n",
				       k * 4 + j, pas_data);
		}
	}
	/*interpolation for even number PAS (2~30)*/
	for (k = 30; k > 0; k -= 2) {
		dpk_info->tmp_pas_i[k] = (dpk_info->tmp_pas_i[k + 1] + dpk_info->tmp_pas_i[k - 1]) >> 1;
		dpk_info->tmp_pas_q[k] = (dpk_info->tmp_pas_q[k + 1] + dpk_info->tmp_pas_q[k - 1]) >> 1;

		if (DPK_PULSE_DBG_8721D) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK] Insert PAS[%02d] = 0x%08x\n",
			       k, (dpk_info->tmp_pas_i[k] << 16) | dpk_info->tmp_pas_q[k]);
		}
	}

	/*for PAS(0)*/
	dpk_info->tmp_pas_i[0] = dpk_info->tmp_pas_i[2] + (dpk_info->tmp_pas_i[1] - dpk_info->tmp_pas_i[3]);
	dpk_info->tmp_pas_q[0] = dpk_info->tmp_pas_q[2] + (dpk_info->tmp_pas_q[1] - dpk_info->tmp_pas_q[3]);

	if (DPK_PULSE_DBG_8721D) {
		for (k = 0; k < 32 ; k++)
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d DPK PAS(interpolated) = 0x%x\n",
			       RF_PATH_A, (dpk_info->tmp_pas_i[k] << 16) | dpk_info->tmp_pas_q[k]);
	}
}

void _dpk_pa_model_write_8721d(struct dm_struct *dm, u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 k;
	u16 byte_0, byte_1, byte_2, byte_3;
	u32 val;

	odm_set_bb_reg(dm, R_0xe28, 0x40000000, 1);

	for (k = 0; k < 0x20 ; k += 2) {
		byte_0 = (dpk_info->tmp_pas_q[31 - k] >> 3) & 0xff;
		byte_1 = (dpk_info->tmp_pas_i[31 - k] >> 3) & 0xff;
		byte_2 = (dpk_info->tmp_pas_q[30 - k] >> 3) & 0xff;
		byte_3 = (dpk_info->tmp_pas_i[30 - k] >> 3) & 0xff;

		val = (byte_3 << 24) | (byte_2 << 16) | (byte_1 << 8) | byte_0;

		odm_set_bb_reg(dm, 0xb00 | (k * 2), MASKDWORD, val);

		if (DPK_PULSE_DBG_8721D)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] S%d PA model 0x%x = 0x%x\n",
			       path, 0xb00 | (k * 2),
			       odm_get_bb_reg(dm, 0xb00 | (k * 2), MASKDWORD));
	}
	odm_set_bb_reg(dm, R_0xe28, 0x40000000, 0);
}

void _dpk_lms_8721d(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x0205e0b8);
	odm_write_1byte(dm, R_0xb07, 0xf7);
	odm_set_bb_reg(dm, R_0xb28, 0xff080000, 0x0);
	odm_set_bb_reg(dm, R_0xb68, MASKHWORD, 0x0285);
	/*0xb68[9:4]threshold,[3:0]turn off tx_ramp*/
	odm_set_bb_reg(dm, R_0xb68, 0x000003ff, 0x30f);
	_dpk_tx_ramp_setting_8721d(dm, TX_FULL_RAMP);
	ODM_delay_ms(1);
	_dpk_one_shot_8721d(dm, GAIN_LOSS);
}

u8 _dpk_gainloss_8721d(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	int k, ret;
	u8 tx_agc_search = 0x0, result[5] = {0x0};

	odm_write_1byte(dm, R_0xb00, 0x38);
	odm_write_1byte(dm, R_0xb07, 0xf7);
	odm_write_1byte(dm, R_0xb2a, 0x08);
	odm_write_1byte(dm, R_0xb2b, 0x00);
	odm_set_bb_reg(dm, R_0xb68, MASKHWORD, 0x159b);
	odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x41382e21);
	ODM_delay_ms(1);

	if (dpk_info->is_dpk_by_channel) {
		/*tx_pulse_ramp*/
		_dpk_tx_ramp_setting_8721d(dm, GAINLOSS_RAMP);
	}

	ret = _dpk_pas_agc_8721d(dm, RF_PATH_A);
	if (ret == 0)
		return 0xff; /*PAScan error*/
	result[0] = (u8)odm_get_bb_reg(dm, R_0xbdc, 0x0000000f);

	RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] result[0] = 0x%x\n", result[0]);

	for (k = 1; k < 5; k++) {
		_dpk_one_shot_8721d(dm, GAIN_LOSS);

		result[k] = (u8)odm_get_bb_reg(dm, R_0xbdc, 0x0000000f);

		RF_DBG(dm, DBG_RF_DPK, "[DPK][GL] result[%d] = 0x%x\n", k,
		       result[k]);

		if (result[k] == result[k - 1])
			break;
	}

	if (k == 4)
		tx_agc_search = ((result[0] + result[1] + result[2] + result[3]
				 + result[4]) / 5);
	else
		tx_agc_search = (u8)odm_get_bb_reg(dm, R_0xbdc, 0x0000000f);

#if 0
	if (DPK_PAS_DBG_8721D)
		_dpk_pas_read_8721d(dm, true);
#endif

	return tx_agc_search;
}

void _dpk_set_tx_agc_8721d(void *dm_void,	u8 retry_cnt)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 reg_b68;
	u8 tx_agc, tx_agc_search, txagc_ori = 0x0;
	s8 txagc_backoff = 0, pwsf_idx = 0;

	if (retry_cnt > 1)
		return;

	tx_agc_search = _dpk_gainloss_8721d(dm);

	if (tx_agc_search == 0xff)
		return;
	ODM_delay_ms(1);

	/*new txagc&& pwsf */
	txagc_backoff = tx_agc_search - 0xa;

	//dpk_info->dpk_txagc += txagc_backoff;

	//pwsf_idx = dpk_info->dpk_txagc - 0x19;

	txagc_ori = odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0x00001f);

	tx_agc = txagc_ori + txagc_backoff;

	pwsf_idx = tx_agc - 0x19;

	/*store (pwsf + 1) offset[14:10]*/
	reg_b68 = 0x11120200 | (((pwsf_idx & 0x1f) + 1) << 10);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x00, RFREG_MASK, (0x50000 | tx_agc));

	odm_set_bb_reg(dm, R_0xb68, MASKDWORD, reg_b68);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] pwsf_idx = 0x%x, tx_agc = 0x%x\n",
	       pwsf_idx, tx_agc);
}

u32 _dpd_calibrate_8721d(void *dm_void, u8 tx_agc_search)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u32 result;
#if 1
	u32 reg_b68;
	u8 tx_agc = 0x0, txagc_ori = 0x0;
	s8 txagc_backoff = 0, pwsf_idx = 0;
	/*new txagc&& pwsf */
	txagc_backoff = tx_agc_search - 0xa;

	txagc_ori = odm_get_rf_reg(dm, RF_PATH_A, RF_0x00, 0x00001f);

	tx_agc = txagc_ori + txagc_backoff;

	pwsf_idx = (tx_agc - 0x19) + 1;

	/*store (pwsf + 1) offset[14:10]*/
	reg_b68 = 0x11120200 | ((pwsf_idx & 0x1f) << 10);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x00, RFREG_MASK, (0x50000 | tx_agc));

	odm_set_bb_reg(dm, R_0xb68, MASKDWORD, reg_b68);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] pwsf_idx = 0x%x, tx_agc = 0x%x\n",
	       pwsf_idx, tx_agc);
#endif
	if (dpk_info->is_dpk_by_channel) {
		odm_set_bb_reg(dm, R_0xb04, MASKDWORD, 0xe7fa9fff);
		odm_write_1byte(dm, R_0xb2b, 0x00);
		odm_write_2byte(dm, R_0xb6a, 0x1113);
		_dpk_tx_ramp_setting_8721d(dm, TX_PULSE_RAMP);
		_dpk_one_shot_8721d(dm, GAIN_LOSS);
		_dpk_pas_interpolation_8721d(dm);
		_dpk_pa_model_write_8721d(dm, RF_PATH_A);
		_dpk_lms_8721d(dm);
	} else {
		odm_write_1byte(dm, R_0xb00, 0x38);
		odm_write_1byte(dm, R_0xb07, 0xf7);
		odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x41382e21);
		odm_write_1byte(dm, R_0xb2b, 0x40);
		odm_write_2byte(dm, R_0xb6a, 0x1112);
		ODM_delay_ms(1);
		_dpk_one_shot_8721d(dm, DO_DPK);
	}
	ODM_delay_ms(2);
	result = odm_get_bb_reg(dm, R_0xbd8, BIT(18));
	RF_DBG(dm, DBG_RF_DPK, "[DPK] fail bit = %x\n", result);
	return result;
}

boolean
_phy_lut_check_8721d(void *dm_void,	u8 addr, BOOLEAN is_even)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 i_val, q_val;

	/*LUT SRAM CHECK I=[21:11],Q=[10:0]*/
	if (is_even) {
		i_val = odm_get_bb_reg(dm, R_0xbe0, 0x003FF800);
		q_val = odm_get_bb_reg(dm, R_0xbe0, 0x000007FF);

	} else {
		i_val = odm_get_bb_reg(dm, R_0xbe4, 0x003FF800);
		q_val = odm_get_bb_reg(dm, R_0xbe4, 0x000007FF);
	}

	/*i/q_val=(S,11.9)*/
	if (((i_val & 0x400) >> 10) == 1)
		i_val = 0x800 - i_val;
	if (((q_val & 0x400) >> 10) == 1)
		q_val = 0x800 - q_val;

	if (addr == 0 && ((i_val * i_val + q_val * q_val) < 0x24000)) {
		/* LMS (I^2 + Q^2) < -2.5dB happen*/
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT < -2.5dB happen, I=0x%x, Q=0x%x\n",
		       i_val, q_val);
		return 1;
	} else if ((i_val * i_val + q_val * q_val) > 0x51000) {
		/* LMS (I^2 + Q^2) > 1dB happen*/
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] LUT > 1dB happen, I=0x%x, Q=0x%x\n",
		       i_val, q_val);
		return 1; /*fail*/
	} else {
		return 0; /*success*/
	}
}

void dpk_on_off_8721d(void *dm_void, boolean turn_on)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	odm_write_1byte(dm, R_0xb00, 0x98);
	odm_write_1byte(dm, R_0xb2b, 0x00);
	odm_write_1byte(dm, R_0xb6a, 0x22);
	if (turn_on)
		odm_write_1byte(dm, R_0xb6b, 0x19); /*bypass pa!=11*/
	else
		odm_write_1byte(dm, R_0xb6b, 0x39); /*bypass dpk*/
	/*GainScaling*/
	odm_write_1byte(dm, R_0xb07, 0x77);
	odm_set_bb_reg(dm, R_0xb08, MASKDWORD, 0x50925092); /*2dB*/
	/*0xb08 0x47CF47CF 1dB */
	/*0xb08 0x4C104C10 1.5dB */
	/*0xb08 0x50925092 2dB */
	/*0xb08 0x55585558 2.5dB */
}

u8 phy_dpk_channel_transfer_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u8 channel, bandwidth, i;

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
		if (channel <= 48)
			i = 3;
		else if (channel >= 52 && channel <= 64)
			i = 4;
		else if (channel >= 100 && channel <= 112)
			i = 5;
		else if (channel >= 116 && channel <= 128)
			i = 6;
		else if (channel >= 132 && channel <= 144)
			i = 7;
		else if (channel >= 149)
			i = 8;
	}

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] channel = %d, bandwidth = %d, transfer idx = %d\n",
	       channel, bandwidth, i);

	return i;
}

u8 _dpk_lut_sram_read_8721d(struct dm_struct *dm,	u8 path, u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr;
	u32 regb2c = 0x0, regbe0 = 0x0, regbe4 = 0x0;

	odm_set_bb_reg(dm, R_0xe38, 0x0c000000, 0x3);
	odm_set_bb_reg(dm, R_0xb04, 0x80000000, 0x1);

	for (addr = 0; addr < 16; addr++) { /*even*/
		regb2c = (0x80000000 | (addr << 24));
		odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, regb2c);
		regbe0 = odm_get_bb_reg(dm, R_0xbe0, 0x003FFFFF);

		if (DPK_SRAM_IQ_DBG_8721D && addr < 16)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] S0[%d] LUT even[%2d] = 0x%x\n",
			       group, addr, regbe0);

		if (_phy_lut_check_8721d(dm, addr, true)) {
			odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);
			return 0;
		}

		if (group < 3)
			dpk_info->lut_2g_even[path][group][addr] = regbe0;
		else
			dpk_info->lut_5g_even[path][group - 3][addr] = regbe0;
	}

	for (addr = 0; addr < 16; addr++) { /*odd*/
		regb2c = (0x80000000 | (addr << 24));
		odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, regb2c);
		regbe4 = odm_get_bb_reg(dm, R_0xbe4, 0x003FFFFF);

		if (DPK_SRAM_IQ_DBG_8721D && addr < 16)
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] S0[%d] LUT  odd[%2d] = 0x%x\n",
			       group, addr, regbe4);

		if (_phy_lut_check_8721d(dm, addr, false)) {
			odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);
			return 0;
		}

		if (group < 3)
			dpk_info->lut_2g_odd[path][group][addr] = regbe4;
		else
			dpk_info->lut_5g_odd[path][group - 3][addr] = regbe4;
	}

	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);

	return 1;
}

void phy_lut_sram_write_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 addr, group, path = 0;
	u32 regb2c_even[16] = {0};
	u32 regb2c_odd[16] = {0};

	group = phy_dpk_channel_transfer_8721d(dm); /*group=0-8*/

	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0xb38, 0x0c000000, 0x3);
	odm_set_bb_reg(dm, R_0xb04, 0x80000000, 0x1);

	for (addr = 0; addr < 16; addr++) {
		/* even*/
		odm_set_bb_reg(dm, R_0xb2c, 0x00c00000, 0x1);
		if (group < 3)
			regb2c_even[addr] =
			dpk_info->lut_2g_even[path][group][addr] & 0x003FFFFF;
		else
			regb2c_even[addr] =
			dpk_info->lut_5g_even[path][group - 3][addr] & 0x3FFFFF;

		odm_set_bb_reg(dm, R_0xb2c, 0x0F000000, addr);
		odm_set_bb_reg(dm, R_0xb2c, 0x003FFFFF, (regb2c_even[addr]));

		if (DPK_SRAM_write_DBG_8721D && addr < 16) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S0[%d] even 0xb2c[%2d] = 0x%x\n",
			       group, addr,
			       odm_get_bb_reg(dm, R_0xb2c, MASKDWORD));
		}
	}

	for (addr = 0; addr < 16; addr++) {
		/* odd*/
		odm_set_bb_reg(dm, R_0xb2c, 0x00c00000, 0x2);
		if (group < 3)
			regb2c_odd[addr] =
			dpk_info->lut_2g_odd[path][group][addr] & 0x003FFFFF;
		else
			regb2c_odd[addr] =
			dpk_info->lut_5g_odd[path][group - 3][addr] & 0x03FFFFF;

		odm_set_bb_reg(dm, R_0xb2c, 0x0F000000, addr);
		odm_set_bb_reg(dm, R_0xb2c, 0x003FFFFF, (regb2c_odd[addr]));

		if (DPK_SRAM_write_DBG_8721D && addr < 16) {
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Write S0[%d]  odd 0xb2c[%2d] = 0x%x\n",
			       group, addr,
			       odm_get_bb_reg(dm, R_0xb2c, MASKDWORD));
		}
	}

	odm_set_bb_reg(dm, R_0xb2c, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0xb04, 0x80000000, 0x0);

	if (group < 3) {
		odm_set_bb_reg(dm, R_0xb68, MASKDWORD,
			       0x11220200 | (dpk_info->pwsf_2g
			       [path][group] << 10));
		RF_DBG(dm, DBG_RF_DPK, "[DPK] W S%d[%d] pwsf = 0x%x\n",
		       path, group, dpk_info->pwsf_2g[path][group]);
	} else {
		odm_set_bb_reg(dm, R_0xb68, MASKDWORD,
			       0x11220200 | (dpk_info->pwsf_5g
			       [path][group - 3] << 10));
		RF_DBG(dm, DBG_RF_DPK, "[DPK] W S%d[%d] pwsf = 0x%x\n",
		       path, group,
		       dpk_info->pwsf_5g[path][group - 3]);
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] Write S0[%d] pwsf = 0x%x\n", group,
	       odm_get_bb_reg(dm, R_0xb68, 0x00007c00));
}

void phy_dpk_enable_disable_8721d(void *dm_void)
{
	/*bypass DPD;*/
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	if (dpk_info->is_dpk_enable) { /*use dpk result*/
		odm_set_bb_reg(dm, R_0xb00, 0x000000ff, 0x98);
		odm_set_bb_reg(dm, R_0xb68, BIT(29), 0x0);
		RF_DBG(dm, DBG_RF_DPK, "[DPK]  DPD enable!!!\n");
	} else { /*bypass dpk result*/
		odm_set_bb_reg(dm, R_0xb00, 0x000000ff, 0x98);
		odm_set_bb_reg(dm, R_0xb68, BIT(29), 0x1);
		RF_DBG(dm, DBG_RF_DPK, "[DPK]  DPD disable!!!\n");
	}
}

void _dpk_rf_setting_8721d(struct dm_struct *dm,	u8 rf_bandtype)
{
	u8 tx_agc_init_value; /* DPK TXAGC value*/
	u32 rf_reg00, rf_IND_VIO1833;

	rf_IND_VIO1833 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x19, RFREG_MASK);

	if (rf_bandtype == ODM_BAND_2_4G) {
		if (rf_IND_VIO1833 & BIT(0)) { /*3.3V*/
			tx_agc_init_value = 0x1C;
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, 0x00008, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x57, 0x00070, 0x5);
			/*PGA gain*/
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, BIT(0), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x8F, 0x06000, 0x0);
		} else { /*1.8V*/
			tx_agc_init_value = 0x1A;
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, 0x00008, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x57, 0x00070, 0x3);
			/*PGA gain*/
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, BIT(0), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x8F, 0x06000, 0x1);
			}
		rf_reg00 = 0x50000 + tx_agc_init_value; /* set TXAGC value*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x00, RFREGOFFSETMASK, rf_reg00);
		odm_set_rf_reg(dm, RF_PATH_A, 0x7c, BIT(0), 0x1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, BIT(8), 0x1);
	} else {
		tx_agc_init_value = 0x1d;
		rf_reg00 = 0x50000 + tx_agc_init_value; /* set TXAGC value*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x00, RFREGOFFSETMASK, rf_reg00);
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, 0x3f000, 0x0f);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, BIT(8), 0x0);
		if (rf_IND_VIO1833 & BIT(0)) {
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, 0x00001, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x8F, 0x06000, 0x0);
		} else {
			odm_set_rf_reg(dm, RF_PATH_A, 0xdd, 0x00001, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, 0x8F, 0x06000, 0x1);
		}
	}
}

void _dpk_result_reset_8721d(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group;

	dpk_info->dpk_path_ok = 0;
	dpk_info->is_dpk_enable = 0;

	for (path = 0; path < DPK_RF_PATH_NUM_8721D; path++) {
		for (group = 0; group < DPK_GROUP_2G_8721D; group++) {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_2g_result[path][group] = 0;
		}
		for (group = 3; group < DPK_GROUP_NUM_8721D; group++) {
			dpk_info->pwsf_5g[path][group - 3] = 0;
			dpk_info->dpk_5g_result[path][group - 3] = 0;
		}
	}
}

void _dpk_do_txiqk_8721d(struct dm_struct *dm)
{
	/*return*/
	u8 iqk_ok = 0, candidate = 0;
	s32 result[1][8];

	odm_set_bb_reg(dm, R_0xb00, 0x000000ff, 0x18);
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);

	iqk_ok = phy_path_a_iqk_8721d(dm);
	if (iqk_ok == 0x01) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]  path A Tx IQK Success!!\n");
		result[0][0] = (odm_get_bb_reg(dm, R_0xe94, MASKDWORD) &
				0x3FF0000) >> 16;
		result[0][1] = (odm_get_bb_reg(dm, R_0xe9c, MASKDWORD) &
				0x3FF0000) >> 16;
	} else {
		RF_DBG(dm, DBG_RF_DPK, "[DPK]  path A Tx IQK Fail!!\n");
		result[0][0] = 0x100;
		result[0][1] = 0x0;
	}
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] result[0][0] = 0x%x, result[0][1] = 0x%x\n",
	       result[0][0], result[0][1]);

	if (result[0][0] != 0)
		_phy_path_a_fill_iqk_matrix_8721d(dm, iqk_ok, result,
						  candidate, true);

	odm_set_bb_reg(dm, R_0xe28, BIT(30), 0x1);
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] IQK finished, 0xb40 = 0x%x, 0xe20 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xb40, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe20, MASKDWORD));
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccc400c0);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00050);
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05611);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000000e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25005000);
	odm_set_bb_reg(dm, R_0xb00, 0x000000ff, 0x98);
}

void _dpk_set_group_8721d(struct dm_struct *dm,	u8 group)
{
	*dm->band_width = CHANNEL_WIDTH_20;
	config_phydm_switch_bandwidth_8721d(dm, 0x1, CHANNEL_WIDTH_20);

	switch (group) {
	case 0: /*channel 3*/
		*dm->band_type = ODM_BAND_2_4G;
		config_phydm_switch_band_8721d(dm, 3);
		config_phydm_switch_channel_8721d(dm, 3);
		*dm->channel = 3;
		break;

	case 1: /*channel 7*/
		config_phydm_switch_channel_8721d(dm, 7);
		*dm->channel = 7;
		break;

	case 2: /*channel 11*/
		config_phydm_switch_channel_8721d(dm, 11);
		*dm->channel = 11;
		break;

	case 3: /*channel 36*/
		*dm->band_type = ODM_BAND_5G;
		config_phydm_switch_band_8721d(dm, 36);
		config_phydm_switch_channel_8721d(dm, 36);
		*dm->channel = 36;
		break;

	case 4: /*channel 64*/
		config_phydm_switch_channel_8721d(dm, 64);
		*dm->channel = 64;
		break;

	case 5: /*channel 100*/
		config_phydm_switch_channel_8721d(dm, 100);
		*dm->channel = 100;
		break;

	case 6: /*channel 120*/
		config_phydm_switch_channel_8721d(dm, 120);
		*dm->channel = 120;
		break;

	case 7: /*channel 140*/
		config_phydm_switch_channel_8721d(dm, 140);
		*dm->channel = 140;
		break;

	case 8: /*channel 165*/
		config_phydm_switch_channel_8721d(dm, 165);
		*dm->channel = 165;
		break;
	default:
		break;
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] switch to group%d, RF0x18 = 0x%x\n",
	       group, odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREG_MASK));
}

void dpk_sram_read_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 path, group, addr;
	u32 temp1, temp2;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Start =========\n");

	for (group = 0; group < DPK_GROUP_NUM_8721D; group++) {
		for (addr = 0; addr < 16; addr++) {
			if (group < 3)
				temp1 = dpk_info->lut_2g_even
					[path][group][addr];
			else
				temp1 =
				dpk_info->lut_5g_even[path][group - 3][addr];

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Read S0[%d] even[%2d] = 0x%x\n",
			       group, addr, temp1);
		}
		for (addr = 0; addr < 16; addr++) {
			if (group < 3)
				temp2 = dpk_info->lut_2g_odd[path][group][addr];
			else
				temp2 =
				dpk_info->lut_5g_odd[path][group - 3][addr];
			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] Read S0[%d]  odd[%2d] = 0x%x\n",
				group, addr, temp2);
		}
	}

	RF_DBG(dm, DBG_RF_DPK, "[DPK] ========= SRAM Read Finish =========\n");
}

u8 _dpk_check_fail_8721d(struct dm_struct *dm,
			 boolean is_fail,
			 u8 path,
			 u8 group)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 result = 0;

	if (!is_fail) {
		if (_dpk_lut_sram_read_8721d(dm, path, group)) {
			if (group < 3) {
				dpk_info->pwsf_2g[path][group] = (u8)
					odm_get_bb_reg(dm, R_0xb68, 0x00007C00);
				dpk_info->dpk_2g_result[path][group] = 1;
			} else {
				dpk_info->pwsf_5g[path][group - 3] = (u8)
					odm_get_bb_reg(dm, R_0xb68, 0x00007C00);
				dpk_info->dpk_5g_result[path][group - 3] = 1;
			}
			result = 1;
		} else {
			if (group < 3) {
				dpk_info->pwsf_2g[path][group] = 0;
				dpk_info->dpk_2g_result[path][group] = 0;
			} else {
				dpk_info->pwsf_5g[path][group - 3] = 0;
				dpk_info->dpk_5g_result[path][group - 3] = 0;
			}
				result = 0;
		}
	} else {
		if (group < 3) {
			dpk_info->pwsf_2g[path][group] = 0;
			dpk_info->dpk_2g_result[path][group] = 0;
		} else {
			dpk_info->pwsf_5g[path][group - 3] = 0;
			dpk_info->dpk_5g_result[path][group - 3] = 0;
		}
		result = 0;
	}

	if (result == 1)
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] ========= S%d[%d] DPK Success ========\n",
		       path, group);
	else
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] ======= S%d[%d] DPK need check =======\n",
		       path, group);
	return result;
}

void _dpk_calibrate_by_group_8721d(struct dm_struct *dm,	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 band_type = 0, dpk_fail = 1, tx_agc_search = 0;
	u8 group, retry_cnt, all_group_success = 0;

	for (group = 0; group < DPK_GROUP_NUM_8721D; group++) {
		_dpk_set_group_8721d(dm, group);
		_dpk_do_txiqk_8721d(dm);
		_dpk_mac_bb_setting_8721d(dm);
		/*For 2g/5g rf setting*/
		band_type = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, 0x10000);
		_dpk_rf_setting_8721d(dm, band_type);

		for (retry_cnt = 0; retry_cnt < 4; retry_cnt++) {
			RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d[%d] retry =%d\n",
			       path, group, retry_cnt);

			RF_DBG(dm, DBG_RF_DPK,
			       "[DPK] ========= S%d[%d] DPK Start =========\n",
			       path, group);

			tx_agc_search = _dpk_gainloss_8721d(dm);

			if (tx_agc_search == 0xff)
				return;

			ODM_delay_ms(1);

			dpk_fail = _dpd_calibrate_8721d(dm, tx_agc_search);

			if (DPK_PAS_DBG_8721D)
				_dpk_pas_read_8721d(dm, false);

			if (_dpk_check_fail_8721d(dm, dpk_fail, path, group)) {
				all_group_success++;
				break;
			}
		}
	}

	if (all_group_success == DPK_GROUP_NUM_8721D)
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);

	if (dpk_info->dpk_path_ok > 0)
		dpk_info->is_dpk_enable = 1;
}

void _dpk_calibrate_by_channel_8721d(struct dm_struct *dm,	u8 path)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	u8 band_type = 0, dpk_fail = 1, tx_agc_search = 0;
	u8 channel, retry_cnt, group = 0;

	channel = *dm->channel;
	band_type = *dm->band_type;

	_dpk_mac_bb_setting_8721d(dm);
	_dpk_rf_setting_8721d(dm, band_type);

	for (retry_cnt = 0; retry_cnt < 4; retry_cnt++) {
		RF_DBG(dm, DBG_RF_DPK, "[DPK] S%d[CH%d] retry =%d\n",
		       path, channel, retry_cnt);

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] ========= S%d[CH%d] DPK Start =========\n",
		       path, channel);

		tx_agc_search = _dpk_gainloss_8721d(dm);

		if (tx_agc_search == 0xff)
			return;

		ODM_delay_ms(1);

		dpk_fail = _dpd_calibrate_8721d(dm, tx_agc_search);

		/*restore registers after LMS function*/
		odm_set_bb_reg(dm, R_0xb00, MASKDWORD, 0x0105f038);
		odm_set_bb_reg(dm, R_0xb04, MASKDWORD, 0xf76d9f84);
		odm_set_bb_reg(dm, R_0xb68, MASKHWORD, 0x1922);
		odm_set_bb_reg(dm, R_0xb68, 0x000003ff, 0x200);
		_dpk_tx_ramp_setting_8721d(dm, TX_INVERSE);

		if (DPK_PAS_DBG_8721D)
			_dpk_pas_read_8721d(dm, false);

		if (_dpk_check_fail_8721d(dm, dpk_fail, path, group))
			break;
	}
	if (dpk_info->dpk_2g_result[path][group])
		dpk_info->dpk_path_ok = dpk_info->dpk_path_ok | BIT(path);

	if (dpk_info->dpk_path_ok > 0)
		dpk_info->is_dpk_enable = 1;
}

void _dpk_path_select_8721d(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

#if (DPK_DO_PATH_A)
	if (dpk_info->is_dpk_by_channel)
		_dpk_calibrate_by_channel_8721d(dm, RF_PATH_A);
	else
		_dpk_calibrate_by_group_8721d(dm, RF_PATH_A);
	if ((dpk_info->dpk_path_ok & BIT(RF_PATH_A)) >> RF_PATH_A)
		dpk_on_off_8721d(dm, true);
	else
		dpk_on_off_8721d(dm, false);
	_dpk_thermal_read_8721d(dm, RF_PATH_A);
#endif
}

void _dpk_result_summary_8721d(struct dm_struct *dm)
{
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path = 0, group;

	if (dpk_info->is_dpk_by_channel)
		return;

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] <======== DPK Result Summary ========>\n");

	for (group = 0; group < DPK_GROUP_2G_8721D; group++) {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] S0[%d] pwsf = 0x%x, dpk_result = %d\n",
		       group, dpk_info->pwsf_2g[path][group],
		       dpk_info->dpk_2g_result[path][group]);
	}

	for (group = 3; group < DPK_GROUP_NUM_8721D; group++) {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK] S0[%d] pwsf = 0x%x, dpk_result = %d\n",
		       group, dpk_info->pwsf_5g[path][group - 3],
		       dpk_info->dpk_5g_result[path][group - 3]);
	}

	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK] S0 DPK is %s\n",
	       ((dpk_info->dpk_path_ok & BIT(path)) >> path) ?
	       "Success" : "Fail");

	RF_DBG(dm, DBG_RF_DPK, "[DPK] dpk_path_ok = 0x%x, dpk_enable = %d\n",
	       dpk_info->dpk_path_ok, dpk_info->is_dpk_enable);

	RF_DBG(dm, DBG_RF_DPK, "[DPK] <======== DPK Result Summary =======>\n");

#if (DPK_SRAM_read_DBG_8721D)
	dpk_sram_read_8721d(dm);
#endif
}

void dpk_reload_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	u8 path;
	struct _hal_rf_ *rf = &dm->rf_table;

	if (!dpk_info->is_dpk_by_channel) {

		/* Ensure don't do dpk if no data in flash when on normal mode*/
		if ((!(*dm->mp_mode)) && !(dm->dpk_info.dpk_path_ok))
			return;
		if (!(rf->rf_supportability & HAL_RF_DPK))
			return;

		phy_lut_sram_write_8721d(dm);

		for (path = 0; path < DPK_RF_PATH_NUM_8721D; path++) {
			if ((dpk_info->dpk_path_ok & BIT(path)) >> path) {
				RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK reload Pass\n");
				dpk_on_off_8721d(dm, true);
			} else {
				RF_DBG(dm, DBG_RF_DPK, "[DPK] DPK reload fail\n");
				dpk_on_off_8721d(dm, false);
			}
		}
	}
	phy_dpk_enable_disable_8721d(dm);
}

void do_dpk_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_DPK, "[DPK]  <============ DPK Start ===========>\n");
	/*u32 mac_reg_backup[DPK_MAC_REG_NUM_8721D];*/
	u32 bb_reg_backup[DPK_BB_REG_NUM_8721D];
	u32 rf_reg_backup[DPK_RF_REG_NUM_8721D][DPK_RF_PATH_NUM_8721D];

	/*u32 mac_reg[DPK_MAC_REG_NUM_8721D] = {0};*/

	u32 bb_reg[DPK_BB_REG_NUM_8721D] = {
		R_0xc04, R_0xc08, R_0x874, R_0x88c, R_0xe70, /*01.BBsetting*/
		R_0x800, R_0xe28, R_0xe3c, R_0xe40, R_0xe44,
		R_0x954, R_0x958, R_0xc3c, R_0xc30, R_0xc84};

	u32 rf_reg[DPK_RF_REG_NUM_8721D] = {
		RF_0x00, RF_0x18, RF_0x57, RF_0x7c, RF_0x8c, RF_0x63,
		RF_0x1a, RF_0x8f, RF_0xdd, RF_0xde, RF_0xee};
	/*backup channel*/
	u8 ori_ch = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, 0x000ff);
	/*backup bandytype*/
	u8 ori_band = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, 0x10000);

	/*phy_dpk_init_8721d(dm);*/
	_backup_mac_bb_registers_8721d(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8721D);
	_backup_rf_registers_8721d(dm, rf_reg, rf_reg_backup);
	_dpk_result_reset_8721d(dm);

	_dpk_path_select_8721d(dm); /*dpk start*/

	_dpk_result_summary_8721d(dm);
	_reload_rf_registers_8721d(dm, rf_reg, rf_reg_backup);
	_reload_mac_bb_registers_8721d(dm, bb_reg, bb_reg_backup,
				       DPK_BB_REG_NUM_8721D);
	*dm->channel = ori_ch;
	*dm->band_type = ori_band;
	config_phydm_switch_channel_8721d(dm, ori_ch);

	dpk_reload_8721d(dm);
}

void phy_dpk_track_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	s8 pwsf_a;
	u8 offset, delta_dpk, is_increase, thermal_value = 0;
	u8 path = 0, thermal_dpk_avg_count = 0, i = 0, k = 0;
	u32 thermal_dpk_avg = 0;

	/* Ensure don't do dpk track if didn't do dpk when on normal mode*/
	if ((!(dpk_info->dpk_path_ok) || !(dm->is_linked)) && !(*dm->mp_mode))
		return;

	if (!dpk_info->thermal_dpk[path])
		dpk_info->thermal_dpk[path] = rf->eeprom_thermal;

	/* calculate average thermal meter */
	/*thermal meter trigger*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_T_METER_8721D,
		       BIT(12) | BIT(11), 0x3);
	ODM_delay_ms(1);
	/*get thermal meter*/
	thermal_value = (u8)odm_get_rf_reg(dm, RF_PATH_A,
					   RF_T_METER_8721D, 0x7e0);
	/*Average times */
	if (dpk_info->thermal_dpk_avg_index == THERMAL_DPK_AVG_NUM)
		dpk_info->thermal_dpk_avg_index = 0;
	dpk_info->thermal_dpk_avg
			[path][dpk_info->thermal_dpk_avg_index] = thermal_value;
	dpk_info->thermal_dpk_avg_index++;

	for (i = 0; i < THERMAL_DPK_AVG_NUM; i++) {
		if (dpk_info->thermal_dpk_avg[path][i]) {
			thermal_dpk_avg += dpk_info->thermal_dpk_avg[path][i];
			thermal_dpk_avg_count++;
		}
	}
	/*Calculate Average ThermalValue after average enough times*/
	if (thermal_dpk_avg_count) {
		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK_track] ThermalValue_DPK_AVG = %d  ThermalValue_DPK_AVG_count = %d\n",
		       thermal_dpk_avg, thermal_dpk_avg_count);

		thermal_value = (u8)(thermal_dpk_avg / thermal_dpk_avg_count);

		RF_DBG(dm, DBG_RF_DPK,
		       "[DPK_track] AVG Thermal Meter = %d, DPK Thermal Meter = %d\n",
		       thermal_value, dpk_info->thermal_dpk[path]);
	}

	/*Calculate pwsf index offset*/
	if (thermal_value >= dpk_info->thermal_dpk[path])
		delta_dpk = thermal_value - dpk_info->thermal_dpk[path];
	else
		delta_dpk = dpk_info->thermal_dpk[path] - thermal_value;
	is_increase = ((thermal_value < dpk_info->thermal_dpk[path]) ? 0 : 1);

	offset = delta_dpk / DPK_THRESHOLD_8721D;
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] delta_DPK = %d, offset = %d, track direction is %s\n",
	       delta_dpk, offset, (is_increase ? "Plus" : "Minus"));

	/*setting new pwsf*/
	if (dpk_info->is_dpk_by_channel) {
		pwsf_a = dpk_info->pwsf_2g[0][0];
	} else {
		k = phy_dpk_channel_transfer_8721d(dm);
		if (*dm->band_type == ODM_BAND_2_4G)
			pwsf_a = dpk_info->pwsf_2g[0][k];
		else
			pwsf_a = dpk_info->pwsf_5g[0][k];
	}
	if ((pwsf_a >> 4) != 0)
		pwsf_a = (pwsf_a | 0xe0);

	if (is_increase)
		pwsf_a = pwsf_a + offset;
	else
		pwsf_a = pwsf_a - offset;

	odm_set_bb_reg(dm, R_0xb68, 0x00007C00, (pwsf_a & 0x1f));
	RF_DBG(dm, DBG_RF_DPK,
	       "[DPK track] pwsf_a after tracking is %d (0x%x), 0xb68 = 0x%x\n",
	       pwsf_a, (pwsf_a & 0x1f), odm_get_bb_reg(dm, R_0xb68, MASKDWORD));
}

void dpk_set_dpkbychannel_8721d(void *dm_void, boolean dpk_by_ch)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_by_channel = dpk_by_ch;
	RF_DBG(dm, DBG_RF_DPK, "[DPK] set_dpkbychannel_8721d\n");
}

boolean dpk_get_dpkbychannel_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] get_dpkbychannel_8721d= %x\n",
	       dpk_info->is_dpk_by_channel);

	return dpk_info->is_dpk_by_channel;
}

void dpk_set_is_dpk_enable_8721d(void *dm_void, boolean is_dpk_enable)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	dpk_info->is_dpk_enable = is_dpk_enable;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] set_is_dpk_enable_8721d\n");
	/*return;*/
}

boolean dpk_get_is_dpk_enable_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_dpk_info *dpk_info = &dm->dpk_info;

	RF_DBG(dm, DBG_RF_DPK, "[DPK] get_is_dpk_enable_8721d= %x\n",
	       dpk_info->is_dpk_enable);
	return dpk_info->is_dpk_enable;
}

#endif
