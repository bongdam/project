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

#if (RTL8197G_SUPPORT == 1)

/*---------------------------Define Local Constant---------------------------*/
void phydm_get_read_counter_8197g(struct dm_struct *dm)
{
	u32 counter = 0x0;

	while (1) {
		if ((odm_get_rf_reg(dm, RF_PATH_A, RF_0x8, RFREGOFFSETMASK) == 0xabcde) || counter > 300)
			break;
		counter++;
		ODM_delay_ms(1);
	};
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x8, RFREGOFFSETMASK, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]counter = %d\n", counter);
}

#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void do_iqk_8197g(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	dm->rf_calibrate_info.thermal_value_iqk = thermal_value;
	halrf_segment_iqk_trigger(dm, true, iqk->segment_iqk);
}
#else
/*Originally config->do_iqk is hooked phy_iq_calibrate_8197G, but do_iqk_8197G and phy_iq_calibrate_8197G have different arguments*/
void do_iqk_8197g(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean is_recovery = (boolean)delta_thermal_index;

	halrf_segment_iqk_trigger(dm, true, iqk->segment_iqk);
}
#endif

static u32
_iqk_btc_wait_indirect_reg_ready_8197g(struct dm_struct *dm)
{
	u32 delay_count = 0;
	
	/* wait for ready bit before access 0x1700 */
	while (1) {
		if ((odm_read_1byte(dm, 0x1703) & BIT(5)) == 0) {
			delay_ms(10);
			if (++delay_count >= 10)
			break;
		} else {
			break;
		}
	}
	
	return delay_count;
}

static u32
_iqk_btc_read_indirect_reg_8197g(struct dm_struct *dm, u16 reg_addr)
{
	u32 delay_count = 0;

	/* wait for ready bit before access 0x1700 */
	_iqk_btc_wait_indirect_reg_ready_8197g(dm);

	odm_write_4byte(dm, 0x1700, 0x800F0000 | reg_addr);

	return odm_read_4byte(dm, 0x1708); /* get read data */
}

static void
_iqk_btc_write_indirect_reg_8197g(struct dm_struct *dm, u16 reg_addr,
		       u32 bit_mask, u32 reg_value)
{
	u32 val, i = 0, bitpos = 0, delay_count = 0;

	if (bit_mask == 0x0)
		return;

	if (bit_mask == 0xffffffff) {
	/* wait for ready bit before access 0x1700 */
	_iqk_btc_wait_indirect_reg_ready_8197g(dm);

	/* put write data */
	odm_write_4byte(dm, 0x1704, reg_value);

	odm_write_4byte(dm, 0x1700, 0xc00F0000 | reg_addr);
	} else {
		for (i = 0; i <= 31; i++) {
			if (((bit_mask >> i) & 0x1) == 0x1) {
				bitpos = i;
				break;
			}
		}

		/* read back register value before write */
		val = _iqk_btc_read_indirect_reg_8197g(dm, reg_addr);
		val = (val & (~bit_mask)) | (reg_value << bitpos);

		/* wait for ready bit before access 0x1700 */
		_iqk_btc_wait_indirect_reg_ready_8197g(dm);

		odm_write_4byte(dm, 0x1704, val); /* put write data */
		odm_write_4byte(dm, 0x1700, 0xc00F0000 | reg_addr);
	}
}

void _iqk_set_gnt_wl_high_8197g(struct dm_struct *dm)
{
	u32 val = 0;
	u8 state = 0x1, sw_control = 0x1;

	/*GNT_WL = 1*/
	val = (sw_control) ? ((state << 1) | 0x1) : 0;
	_iqk_btc_write_indirect_reg_8197g(dm, 0x38, 0x3000, val); /*0x38[13:12]*/
	_iqk_btc_write_indirect_reg_8197g(dm, 0x38, 0x0300, val); /*0x38[9:8]*/
}

void _iqk_set_gnt_bt_low_8197g(struct dm_struct *dm)
{
	u32 val = 0;
	u8 state = 0x0, sw_control = 0x1;

	/*GNT_BT = 0*/
	val = (sw_control) ? ((state << 1) | 0x1) : 0;
	_iqk_btc_write_indirect_reg_8197g(dm, 0x38, 0xc000, val); /*0x38[15:14]*/
	_iqk_btc_write_indirect_reg_8197g(dm, 0x38, 0x0c00, val); /*0x38[11:10]*/
}

void _iqk_set_gnt_wl_gnt_bt_8197g(struct dm_struct *dm, boolean beforeK)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (beforeK) {
		_iqk_set_gnt_wl_high_8197g(dm);
		_iqk_set_gnt_bt_low_8197g(dm);
	} else {
		_iqk_btc_write_indirect_reg_8197g(dm, 0x38, MASKDWORD, iqk->tmp_gntwl);
	}
}

void _iqk_clean_cfir_8197g(struct dm_struct *dm, u8 mode, u8 path)
{
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
	if (mode == TXIQK) {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
		odm_write_4byte(dm, 0x1bd8, 0xc0000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	}
	else {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);
		odm_write_4byte(dm, 0x1bd8, 0x60000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	}		

	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
	odm_write_4byte(dm, 0x1bd8, 0x0);
}

void _iqk_cal_path_off_8197g(struct dm_struct *dm)
{
	u8 path;

	for(path = 0; path < SS_8197G; path++) {
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
//		odm_set_bb_reg(dm, R_0x1b00, BIT(2)| BIT(1), path);
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		odm_set_bb_reg(dm, 0x1bcc, 0x3f, 0x3f);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x0, 0xfffff, 0x10000);
	}
}

void _iqk_rf_set_check_8197g(
	struct dm_struct *dm,
	u8 path,
	u16 add,
	u32 data)
{
	u32 i;

	odm_set_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK, data);

	for (i = 0; i < 100; i++) {
		if (odm_get_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK) == data)
			break;
		else {
			ODM_delay_us(10);
			odm_set_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK, data);
		}
	}
}

void _iqk_rf0xb0_workaround_8197g(
	struct dm_struct *dm)
{
	/*add 0xb8 control for the bad phase noise after switching channel*/
	odm_set_rf_reg(dm, (enum rf_path)0x0, RF_0xb8, RFREGOFFSETMASK, 0x00a00);
	odm_set_rf_reg(dm, (enum rf_path)0x0, RF_0xb8, RFREGOFFSETMASK, 0x80a00);
}

void _iqk_fill_iqk_report_8197g(
	void *dm_void,
	u8 channel)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 tmp1 = 0x0, tmp2 = 0x0, tmp3 = 0x0;
	u8 i;

	for (i = 0; i < SS_8197G; i++) {
		tmp1 = tmp1 + ((iqk->iqk_fail_report[channel][i][TX_IQK] & 0x1) << i);
		tmp2 = tmp2 + ((iqk->iqk_fail_report[channel][i][RX_IQK] & 0x1) << (i + 4));
		tmp3 = tmp3 + ((iqk->rxiqk_fail_code[channel][i] & 0x3) << (i * 2 + 8));
	}
	odm_write_4byte(dm, 0x1b00, 0x8);
	odm_set_bb_reg(dm, R_0x1bf0, 0x0000ffff, tmp1 | tmp2 | tmp3);

	tmp1 = 0x0;
	for (i = 0; i < SS_8197G; i++)
		tmp1 = tmp1 | (iqk->rxiqk_agc[channel][i] << (i*8));
	odm_write_4byte(dm, 0x1be8, tmp1);
}

void _iqk_fail_count_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;

	dm->n_iqk_cnt++;
	if (odm_get_rf_reg(dm, RF_PATH_A, RF_0x1bf0, BIT(16)) == 1)
		iqk->is_reload = true;
	else
		iqk->is_reload = false;

	if (!iqk->is_reload) {
		for (i = 0; i < 8; i++) {
			if (odm_get_bb_reg(dm, R_0x1bf0, BIT(i)) == 1)
				dm->n_iqk_fail_cnt++;
		}
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]All/Fail = %d %d\n", dm->n_iqk_cnt, dm->n_iqk_fail_cnt);
}

void _iqk_iqk_fail_report_8197g(
	struct dm_struct *dm)
{
	u32 tmp1bf0 = 0x0;
	u8 i;

	tmp1bf0 = odm_read_4byte(dm, 0x1bf0);

	for (i = 0; i < 4; i++) {
		if (tmp1bf0 & (0x1 << i))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d TXIQK\n", i);
#else
			panic_printk("[IQK] please check S%d TXIQK\n", i);
#endif
		if (tmp1bf0 & (0x1 << (i + 12)))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d RXIQK\n", i);
#else
			panic_printk("[IQK] please check S%d RXIQK\n", i);
#endif
	}
}

void _iqk_backup_mac_bb_8197g(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;
	for (i = 0; i < MAC_REG_NUM_8197G; i++){
		MAC_backup[i] = odm_read_4byte(dm, backup_mac_reg[i]);
		//RF_DBG(dm, DBG_RF_IQK, "[IQK]Backup mac addr = %x, value =% x\n", backup_mac_reg[i], MAC_backup[i]);
	}
	for (i = 0; i < BB_REG_NUM_8197G; i++){
		BB_backup[i] = odm_read_4byte(dm, backup_bb_reg[i]);		
		//RF_DBG(dm, DBG_RF_IQK, "[IQK]Backup bbaddr = %x, value =% x\n", backup_bb_reg[i], BB_backup[i]);
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]BackupMacBB Success!!!!\n"); 
}

void _iqk_backup_rf_8197g(
	struct dm_struct *dm,
	u32 RF_backup[][SS_8197G],
	u32 *backup_rf_reg)
{
	u32 i;

	for (i = 0; i < RF_REG_NUM_8197G; i++) {
		RF_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A, backup_rf_reg[i], RFREGOFFSETMASK);
		RF_backup[i][RF_PATH_B] = odm_get_rf_reg(dm, RF_PATH_B, backup_rf_reg[i], RFREGOFFSETMASK);
		//RF_backup[i][RF_PATH_C] = odm_get_rf_reg(dm, RF_PATH_C, backup_rf_reg[i], RFREGOFFSETMASK);
		//RF_backup[i][RF_PATH_D] = odm_get_rf_reg(dm, RF_PATH_D, backup_rf_reg[i], RFREGOFFSETMASK);
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]BackupRF Success!!!!\n"); 
}

void _iqk_agc_bnd_int_8197g(
	struct dm_struct *dm)
{
	return;
	/*initialize RX AGC bnd, it must do after bbreset*/
	odm_write_4byte(dm, 0x1b00, 0x8);
	odm_write_4byte(dm, 0x1b00, 0x00A70008);
	odm_write_4byte(dm, 0x1b00, 0x00150008);
	odm_write_4byte(dm, 0x1b00, 0x8);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]init. rx agc bnd\n");
}

void _iqk_bb_reset_8197g(
	struct dm_struct *dm)
{
	boolean cca_ing = false;
	u32 count = 0;

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, RFREGOFFSETMASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x0, RFREGOFFSETMASK, 0x10000);
	/*reset BB report*/
	odm_set_bb_reg(dm, R_0x8f8, 0x0ff00000, 0x0);

	while (1) {
		odm_write_4byte(dm, 0x8fc, 0x0);
		odm_set_bb_reg(dm, R_0x198c, 0x7, 0x7);
		cca_ing = (boolean)odm_get_bb_reg(dm, R_0xfa0, BIT(3));

		if (count > 30)
			cca_ing = false;

		if (cca_ing) {
			ODM_delay_ms(1);
			count++;
		} else {
			odm_write_1byte(dm, 0x808, 0x0); /*RX ant off*/
			odm_set_bb_reg(dm, R_0xa04, BIT(27) | BIT(26) | BIT(25) | BIT(24), 0x0); /*CCK RX path off*/

			/*BBreset*/
			odm_set_bb_reg(dm, R_0x0, BIT(16), 0x0);
			odm_set_bb_reg(dm, R_0x0, BIT(16), 0x1);

			if (odm_get_bb_reg(dm, R_0x660, BIT(16)))
				odm_write_4byte(dm, 0x6b4, 0x89000006);
			/*RF_DBG(dm, DBG_RF_IQK, "[IQK]BBreset!!!!\n");*/
			break;
		}
	}
}
void _iqk_bb_for_dpk_setting_8197g(struct dm_struct *dm)
{
	odm_set_bb_reg(dm, R_0x1e24, BIT(17), 0x1);
	odm_set_bb_reg(dm, R_0x1cd0, BIT(28), 0x1);
	odm_set_bb_reg(dm, R_0x1cd0, BIT(29), 0x1);
	odm_set_bb_reg(dm, R_0x1cd0, BIT(30), 0x1);
	odm_set_bb_reg(dm, R_0x1cd0, BIT(31), 0x0);
	//odm_set_bb_reg(dm, R_0x1c68, 0x0f000000, 0xf);	
	odm_set_bb_reg(dm, 0x1d58, 0xff8, 0x1ff);
	odm_set_bb_reg(dm, 0x1864, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x4164, BIT(31), 0x1);
	odm_set_bb_reg(dm, R_0x180c, BIT(27), 0x1);
	odm_set_bb_reg(dm, R_0x410c, BIT(27), 0x1);
	odm_set_bb_reg(dm, R_0x186c, BIT(7), 0x1);
	odm_set_bb_reg(dm, 0x416c, BIT(7), 0x1);
	odm_set_bb_reg(dm, R_0x180c, 0x3, 0x0); //S0 -3 wire
	odm_set_bb_reg(dm, R_0x410c, 0x3, 0x0); //S1 -3wire
	odm_set_bb_reg(dm, 0x1a00, BIT(1) | BIT(0), 0x2);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]_iqk_bb_for_dpk_setting_8197g!!!!\n");
}

void _iqk_rf_setting_8197g(struct dm_struct *dm)
{	
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	/*TxIQK mode S0,RF0x00[19:16]=0x4*/
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x80000);
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0x0000f, 0x4);
	odm_set_rf_reg(dm, RF_PATH_A, 0x3e, 0xfffff, 0x00003);
	odm_set_rf_reg(dm, RF_PATH_A, 0x3f, 0xfffff, 0xF60FF);//3F[15]=0, iPA off 
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x00000);

	/*TxIQK mode S1,RF0x00[19:16]=0x4*/
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x80000);
	odm_set_rf_reg(dm, RF_PATH_B, 0x33, 0x0000f, 0x4);
	odm_set_rf_reg(dm, RF_PATH_B, 0x3f, 0xfffff, 0xFD83F);//3F[15]=0, iPA off 
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x00000);

	// RxIQK1 mode S0, RF0x00[19:16]=0x6
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x80000); //[19]: WE_LUT_RFMODE
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0x0000f, 0x6); //RFMODE
	odm_set_rf_reg(dm, RF_PATH_A, 0x3e, 0xfffff, 0x00003);
	odm_set_rf_reg(dm, RF_PATH_A, 0x3f, 0xfffff, 0x760FF);//3F[15]=0, iPA off , 3F[19]=0, POW_TXBB off
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x00000);

	// RxIQK1 mode S1, RF0x00[19:16]=0x6
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x80000);
	odm_set_rf_reg(dm, RF_PATH_B, 0x33, 0x0000f, 0x6);
	odm_set_rf_reg(dm, RF_PATH_B, 0x3f, 0xfffff, 0xDD83F);//3F[15]=0, iPA off 
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x00000);

	// RxIQK2 mode S0, RF0x00[19:16]=0x7	
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x80000); //[19]: WE_LUT_RFMODE
	odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0x0000f, 0x7); //RFMODE
	odm_set_rf_reg(dm, RF_PATH_A, 0x3e, 0xfffff, 0x00003);
	odm_set_rf_reg(dm, RF_PATH_A, 0x3f, 0xfffff, 0x7DEFF);//3F[15]=1, iPA on ,3F[19]=0, POW_TXBB off
	odm_set_rf_reg(dm, RF_PATH_A, 0xef, 0xfffff, 0x00000);

	// RxIQK2 mode S1, RF0x00[19:16]=0x7
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x80000); //[19]: WE_LUT_RFMODE
	odm_set_rf_reg(dm, RF_PATH_B, 0x33, 0x0000f, 0x7); //RFMODE
	odm_set_rf_reg(dm, RF_PATH_B, 0x3f, 0xfffff, 0xDF7BF);//3F[13]=1, iPA on ,3F[17]=0, POW_TXBB off
	odm_set_rf_reg(dm, RF_PATH_B, 0xef, 0xfffff, 0x00000);

	
	RF_DBG(dm, DBG_RF_IQK, "[IQK]_iqk_rf_setting_8197g RF01!!!!\n");
}

void _iqk_afe_setting_8197g(
	struct dm_struct *dm,
	boolean do_iqk)
{
	u8 i;

	if (do_iqk) {
		/*03_8197G_AFE_for_DPK.txt*/
		// AFE on Settings
		odm_write_4byte(dm, 0x1c38, 0xffffffff); //AD/DA both on
		odm_write_4byte(dm, 0x1810, 0xB3001402);
		odm_write_4byte(dm, 0x1814, 0x06000141);
		odm_write_4byte(dm, 0x1818, 0x00000280);
		odm_write_4byte(dm, 0x181c, 0x00000000);
		odm_write_4byte(dm, 0x4110, 0xB3001402);
		odm_write_4byte(dm, 0x4114, 0x06000141);
		odm_write_4byte(dm, 0x4118, 0x00000280);
		odm_write_4byte(dm, 0x411c, 0x00000000);

		odm_write_4byte(dm, 0x1830, 0x700f0001);
		odm_write_4byte(dm, 0x1830, 0x700f0001);
		odm_write_4byte(dm, 0x1830, 0x701f0001);
		odm_write_4byte(dm, 0x1830, 0x702f0001);
		odm_write_4byte(dm, 0x1830, 0x703f0001);
		odm_write_4byte(dm, 0x1830, 0x704f0001);
		odm_write_4byte(dm, 0x1830, 0x705f0001);
		odm_write_4byte(dm, 0x1830, 0x706f0001);
		odm_write_4byte(dm, 0x1830, 0x707f0001);
		odm_write_4byte(dm, 0x1830, 0x708f0001);
		odm_write_4byte(dm, 0x1830, 0x709f0001);
		odm_write_4byte(dm, 0x1830, 0x70af0001);
		odm_write_4byte(dm, 0x1830, 0x70bf0001);
		odm_write_4byte(dm, 0x1830, 0x70cf0001);
		odm_write_4byte(dm, 0x1830, 0x70df0001);
		odm_write_4byte(dm, 0x1830, 0x70ef0001);
		odm_write_4byte(dm, 0x1830, 0x70ff0001);
		odm_write_4byte(dm, 0x1830, 0x70ff0001);
		odm_write_4byte(dm, 0x4130, 0x700f0001);
		odm_write_4byte(dm, 0x4130, 0x700f0001);
		odm_write_4byte(dm, 0x4130, 0x701f0001);
		odm_write_4byte(dm, 0x4130, 0x702f0001);
		odm_write_4byte(dm, 0x4130, 0x703f0001);
		odm_write_4byte(dm, 0x4130, 0x704f0001);
		odm_write_4byte(dm, 0x4130, 0x705f0001);
		odm_write_4byte(dm, 0x4130, 0x706f0001);
		odm_write_4byte(dm, 0x4130, 0x707f0001);
		odm_write_4byte(dm, 0x4130, 0x708f0001);
		odm_write_4byte(dm, 0x4130, 0x709f0001);
		odm_write_4byte(dm, 0x4130, 0x70af0001);
		odm_write_4byte(dm, 0x4130, 0x70bf0001);
		odm_write_4byte(dm, 0x4130, 0x70cf0001);
		odm_write_4byte(dm, 0x4130, 0x70df0001);
		odm_write_4byte(dm, 0x4130, 0x70ef0001);
		odm_write_4byte(dm, 0x4130, 0x70ff0001);
		odm_write_4byte(dm, 0x4130, 0x70ff0001);		
		RF_DBG(dm, DBG_RF_IQK, "[IQK]AFE setting for IQK mode!!!!\n");
	} else {
		// AFE Restore Settings
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x1830, MASKDWORD, 0x70fb8041);

		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x700b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70144041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70244041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70344041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70444041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x705b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70644041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x707b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x708b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x709b8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70ab8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70bb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70cb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70db8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70eb8041);
		odm_set_bb_reg(dm, R_0x4130, MASKDWORD, 0x70fb8041);


		/*11_8197G_BB_for_DPK_restore*/
//		odm_set_bb_reg(dm, 0x1d0c, BIT(16), 0x1);
//		odm_set_bb_reg(dm, 0x1d0c, BIT(16), 0x0);
//		odm_set_bb_reg(dm, 0x1d0c, BIT(16), 0x1);

//		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
//		odm_set_bb_reg(dm, 0x1bcc, 0x000000ff, 0x0);

		// BB Restore Settings
		//odm_set_bb_reg(dm, 0x1c68, 0x0f000000, 0x0);
//		odm_set_bb_reg(dm, 0x1d58, 0xff8, 0x0);
		//odm_set_bb_reg(dm, 0x1c3c, BIT(0), 0x1);
		//odm_set_bb_reg(dm, 0x1c3c, BIT(1), 0x1);
//		odm_set_bb_reg(dm, 0x1864, BIT(31), 0x0);
//		odm_set_bb_reg(dm, 0x4164, BIT(31), 0x0);
//		odm_set_bb_reg(dm, 0x180c, BIT(27), 0x0);
//		odm_set_bb_reg(dm, 0x410c, BIT(27), 0x0);
//		odm_set_bb_reg(dm, 0x186c, BIT(7), 0x0);
//		odm_set_bb_reg(dm, 0x416c, BIT(7), 0x0);
//		odm_set_bb_reg(dm, 0x180c, BIT(1) | BIT(0), 0x3);
//		odm_set_bb_reg(dm, 0x410c, BIT(1) | BIT(0), 0x3);

//		odm_set_bb_reg(dm, 0x1a00, BIT(1) | BIT(0), 0x0);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]AFE setting for Normal mode!!!!\n");
	}
}

void _iqk_restore_mac_bb_8197g(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;
	//97G
	
	/*toggle IGI*/
	//odm_write_4byte(dm, 0x1d70, 0x50505050);

	for (i = 0; i < MAC_REG_NUM_8197G; i++){
		odm_write_4byte(dm, backup_mac_reg[i], MAC_backup[i]);
		//RF_DBG(dm, DBG_RF_IQK, "[IQK]restore mac = %x, value = %x\n",backup_mac_reg[i],MAC_backup[i]);
		}
	for (i = 0; i < BB_REG_NUM_8197G; i++){
		odm_write_4byte(dm, backup_bb_reg[i], BB_backup[i]);		
		//RF_DBG(dm, DBG_RF_IQK, "[IQK]restore bb = %x, value = %x\n",backup_bb_reg[i],BB_backup[i]);
		}
	/*rx go throughput IQK*/
//	odm_set_bb_reg(dm, 0x180c, BIT(31), 0x1);
//	odm_set_bb_reg(dm, 0x410c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x1e24, BIT(31), 0x1);
	//odm_set_bb_reg(dm, 0x520c, BIT(31), 0x1);
	//odm_set_bb_reg(dm, 0x530c, BIT(31), 0x1);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]RestoreMacBB Success!!!!\n"); */
}

void _iqk_restore_rf_8197g(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 temp[][SS_8197G])
{
	u32 i;
	
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, 0xfffff, 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, 0xfffff, 0x0);
	/*0xdf[4]=0*/
	//_iqk_rf_set_check_8197g(dm, RF_PATH_A, 0xdf, temp[0][RF_PATH_A] & (~BIT(4)));
	//_iqk_rf_set_check_8197g(dm, RF_PATH_B, 0xdf, temp[0][RF_PATH_B] & (~BIT(4)));

	for (i = 0; i < RF_REG_NUM_8197G; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i],
			       0xfffff, temp[i][RF_PATH_A]);
		odm_set_rf_reg(dm, RF_PATH_B, rf_reg[i],
			       0xfffff, temp[i][RF_PATH_B]);
	}
	
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, BIT(16), 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xde, BIT(16), 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]RestoreRF Success!!!!\n"); 
}

void _iqk_backup_iqk_8197g(
	struct dm_struct *dm,
	u8 step,
	u8 path)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k;

	switch (step) {
	case 0:
		iqk->iqk_channel[1] = iqk->iqk_channel[0];
		for (i = 0; i < SS_8197G; i++) {
			iqk->lok_idac[1][i] = iqk->lok_idac[0][i];
			iqk->rxiqk_agc[1][i] = iqk->rxiqk_agc[0][i];
			iqk->bypass_iqk[1][i] = iqk->bypass_iqk[0][i];
			iqk->rxiqk_fail_code[1][i] = iqk->rxiqk_fail_code[0][i];
			for (j = 0; j < 2; j++) {
				iqk->iqk_fail_report[1][i][j] = iqk->iqk_fail_report[0][i][j];
				for (k = 0; k < 8; k++) {
					iqk->iqk_cfir_real[1][i][j][k] = iqk->iqk_cfir_real[0][i][j][k];
					iqk->iqk_cfir_imag[1][i][j][k] = iqk->iqk_cfir_imag[0][i][j][k];
				}
			}
		}

		for (i = 0; i < SS_8197G; i++) {
			iqk->rxiqk_fail_code[0][i] = 0x0;
			iqk->rxiqk_agc[0][i] = 0x0;
			for (j = 0; j < 2; j++) {
				iqk->iqk_fail_report[0][i][j] = true;
				iqk->gs_retry_count[0][i][j] = 0x0;
			}
			for (j = 0; j < 3; j++)
				iqk->retry_count[0][i][j] = 0x0;
		}
		/*backup channel*/
		iqk->iqk_channel[0] = iqk->rf_reg18;
		break;
	case 1: /*LOK backup*/
		iqk->lok_idac[0][path] = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, RFREGOFFSETMASK);
		break;
	case 2: /*TXIQK backup*/
	case 3: /*RXIQK backup*/
		phydm_get_iqk_cfir(dm, (step - 2), path, false);
		break;
	}
}

void _iqk_reload_iqk_setting_8197g(
	struct dm_struct *dm,
	u8 channel,
	u8 reload_idx /*1: reload TX, 2: reload LO, TX, RX*/
	)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
#if 1
	u8 i, path, idx;
	//u16 iqk_apply[2] = {0xc94, 0xe94};
	u16 iqk_apply[2] = {0x180c, 0x410c};
	u32 tmp;

	for (path = 0; path < SS_8197G; path++) {
		if (reload_idx == 2) {
			/*odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x1);*/
			tmp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0xdf, RFREGOFFSETMASK) | BIT(4);
			_iqk_rf_set_check_8197g(dm, (enum rf_path)path, 0xdf, tmp);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x58, RFREGOFFSETMASK, iqk->lok_idac[channel][path]);
		}

		for (idx = 0; idx < reload_idx; idx++) {
			odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
			odm_set_bb_reg(dm, R_0x1b2c, MASKDWORD, 0x7);
			odm_set_bb_reg(dm, R_0x1b38, MASKDWORD, 0x40000000);
			odm_set_bb_reg(dm, R_0x1b3c, MASKDWORD, 0x40000000);
			odm_write_1byte(dm, 0x1bcc, 0x0);

			if (idx == 0)
				odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
			else
				odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);
			odm_set_bb_reg(dm, R_0x1bd4, BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16), 0x10);
			for (i = 0; i < 8; i++) {
				odm_write_4byte(dm, 0x1bd8, ((0xc0000000 >> idx) + 0x3) + (i * 4) + (iqk->iqk_cfir_real[channel][path][idx][i] << 9));
				odm_write_4byte(dm, 0x1bd8, ((0xc0000000 >> idx) + 0x1) + (i * 4) + (iqk->iqk_cfir_imag[channel][path][idx][i] << 9));
			}
			if (idx == 0)
				odm_set_bb_reg(dm, iqk_apply[path], BIT(31), ~(iqk->iqk_fail_report[channel][path][idx]));
			else
				odm_set_bb_reg(dm, iqk_apply[path], BIT(31), ~(iqk->iqk_fail_report[channel][path][idx]));
		}
		odm_set_bb_reg(dm, R_0x1bd8, MASKDWORD, 0x0);
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
	}
#endif
}

boolean
_iqk_reload_iqk_8197g(
	struct dm_struct *dm,
	boolean reset)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;
	iqk->is_reload = false;

	if (reset) {
		for (i = 0; i < 2; i++)
			iqk->iqk_channel[i] = 0x0;
	} else {
		iqk->rf_reg18 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK);

		for (i = 0; i < 2; i++) {
			if (iqk->rf_reg18 == iqk->iqk_channel[i]) {
				_iqk_reload_iqk_setting_8197g(dm, i, 2);
				_iqk_fill_iqk_report_8197g(dm, i);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]reload IQK result before!!!!\n");
				iqk->is_reload = true;
			}
		}
	}
	/*report*/
	odm_set_bb_reg(dm, R_0x1bf0, BIT(16), (u8)iqk->is_reload);
	return iqk->is_reload;
}

void _iqk_rfe_setting_8197g(
	struct dm_struct *dm,
	boolean ext_pa_on)
{
	/*TBD*/
	return;
	if (ext_pa_on) {
		/*RFE setting*/
		odm_write_4byte(dm, 0xcb0, 0x77777777);
		odm_write_4byte(dm, 0xcb4, 0x00007777);
		odm_write_4byte(dm, 0xcbc, 0x0000083B);
		odm_write_4byte(dm, 0xeb0, 0x77777777);
		odm_write_4byte(dm, 0xeb4, 0x00007777);
		odm_write_4byte(dm, 0xebc, 0x0000083B);
		/*odm_write_4byte(dm, 0x1990, 0x00000c30);*/
		RF_DBG(dm, DBG_RF_IQK, "[IQK]external PA on!!!!\n");
	} else {
		/*RFE setting*/
		odm_write_4byte(dm, 0xcb0, 0x77777777);
		odm_write_4byte(dm, 0xcb4, 0x00007777);
		odm_write_4byte(dm, 0xcbc, 0x00000100);
		odm_write_4byte(dm, 0xeb0, 0x77777777);
		odm_write_4byte(dm, 0xeb4, 0x00007777);
		odm_write_4byte(dm, 0xebc, 0x00000100);
		/*odm_write_4byte(dm, 0x1990, 0x00000c30);*/
		/*RF_DBG(dm, DBG_RF_IQK, "[IQK]external PA off!!!!\n");*/
	}
}

void _iqk_setrf_bypath_8197g(
	struct dm_struct *dm)
{
	u8 path;
	u32 tmp;

	/*TBD*/
}
void _iqk_rf_direct_access_8197g(
	struct dm_struct *dm,
	u8 path,
	boolean direct_access)
{
	if(!direct_access) {//PI	
		if ((enum rf_path)path == RF_PATH_A)
			odm_set_bb_reg(dm, 0x1c, BIT(31) | BIT(30), 0x0);
		else if((enum rf_path)path == RF_PATH_B)
			odm_set_bb_reg(dm, 0xec, BIT(31) | BIT(30), 0x0);
		//odm_set_bb_reg(dm, 0x1c, BIT(31) | BIT(30), 0x0);	
		//odm_set_bb_reg(dm, 0xec, BIT(31) | BIT(30), 0x0);
	} else {//direct access
		if ((enum rf_path)path == RF_PATH_A)
			odm_set_bb_reg(dm, 0x1c, BIT(31) | BIT(30), 0x2);
		else if((enum rf_path)path == RF_PATH_B)
			odm_set_bb_reg(dm, 0xec, BIT(31) | BIT(30), 0x2);
		//odm_set_bb_reg(dm, 0x1c, BIT(31) | BIT(30), 0x2);
		//odm_set_bb_reg(dm, 0xec, BIT(31) | BIT(30), 0x2);
	}
	/*
	RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1c = 0x%x, 0xec = 0x%x\n",
	       odm_read_4byte(dm, 0x1c), odm_read_4byte(dm, 0xec));
	*/
}

void _iqk_bbtx_path_8197g(
	struct dm_struct *dm,
	u8 path)
{
	u32 temp1 = 0, temp2 = 0;

	switch (path) {
	case RF_PATH_A:
		temp1 = 0x11111111;
		temp2 = 0x1;
		break;
	case RF_PATH_B:
		temp1 = 0x22222222;
		temp2 = 0x2;
		break;
	}
	odm_write_4byte(dm, 0x820, temp1);
	odm_set_bb_reg(dm, 0x824, 0xf0000, temp2);
}

void _iqk_iqk_mode_8197g(
	struct dm_struct *dm,
	boolean is_iqkmode)
{
	u32 temp1, temp2;
	/*RF can't be write in iqk mode*/
	/*page 1b can't */
	if (is_iqkmode)
		odm_set_bb_reg(dm, 0x1cd0, BIT(31), 0x1);
	else
		odm_set_bb_reg(dm, 0x1cd0, BIT(31), 0x0);	
}

void _iqk_macbb_8197g(
	struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, REG_TXPAUSE, 0xff);
	/*BB setting*/
	/*ADDA FIFO reset*/
//	odm_write_4byte(dm, 0x1c38, 0xffffffff);
	odm_set_bb_reg(dm, 0x1e24, BIT(31), 0x0);
	odm_set_bb_reg(dm, 0x1e28, 0xf, 0x3);
	odm_set_bb_reg(dm, 0x0824, 0xf0000, 0x3);	
	odm_write_4byte(dm, 0x1808, 0x00050000);
	odm_write_4byte(dm, 0x4108, 0x00070000);
	odm_set_bb_reg(dm, 0x1a00, 0x3, 0x2);
	odm_set_bb_reg(dm, 0x1e24, BIT(17), 0x1);
	/*turn off CCA*/
	odm_set_bb_reg(dm, 0x1d58, BIT(3), 0x1);
	odm_set_bb_reg(dm, 0x1d58, 0xff0, 0xff);

	odm_set_bb_reg(dm, 0x1864, BIT(31), 0x1);	
	odm_set_bb_reg(dm, 0x4164, BIT(31), 0x1);	
	odm_set_bb_reg(dm, 0x180c, BIT(27), 0x1);	
	odm_set_bb_reg(dm, 0x410c, BIT(27), 0x1);	
	odm_set_bb_reg(dm, 0x180c, 0x3, 0x0);	
	odm_set_bb_reg(dm, 0x410c, 0x3, 0x0);	
}

void _iqk_lok_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
	u32 temp;
	_iqk_cal_path_off_8197g(dm);
	//_iqk_bbtx_path_8197g(dm, path);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	
	odm_set_bb_reg(dm, 0x1b20, BIT(31) | BIT(30), 0x0);
	odm_set_bb_reg(dm, 0x1b20, 0x3e0, 0x12);// 12dB
	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x0);
	// Disable bypass TXBB @ RF0x0[19:16]=0x6 and 0x7
	odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(5), 0x0);		
	odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(10), 0x0);

	
	//LOK_RES Table
	if (*dm->band_type == ODM_BAND_2_4G) {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x887);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x18, BIT(16), 0x0);
		//odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, BIT(0), 0x0);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0x70, 0x4);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x0);		
	} else {	
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x868);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x18, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, BIT(0), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0x70, 0x4);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x0);
	}	
	odm_set_rf_reg(dm, (enum rf_path)path, 0x57, BIT(0), 0x0);

//TX_LOK
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
	if (*dm->band_type == ODM_BAND_2_4G) {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x00);
		odm_write_1byte(dm, 0x1bcc, 0x09);		
		odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x38);
	} else {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x20);
		odm_write_1byte(dm, 0x1bcc, 0x09);
		odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x38);
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
}

void _iqk_reload_lok_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
#if 1
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 tmp;
	u8 idac_i, idac_q;
	u8 i;

	idac_i = (u8)((iqk->rf_reg58 & 0xfc000) >> 14);
	idac_q = (u8)((iqk->rf_reg58 & 0x3f00) >> 8);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x0);//W LOK table
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);

	if (*dm->band_type == ODM_BAND_2_4G)
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x00);
	else
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x20);

	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0xfc000, idac_i);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0x003f0, idac_q);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);// stop write
	
	tmp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d,reload 0x58 = 0x%x\n", path, tmp);
#endif
}

void _iqk_txk_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
	//_iqk_bbtx_path_8197g(dm, path);
	_iqk_cal_path_off_8197g(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, 0xc, 0x3);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0x1fff, 0x1c6e);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0xe000, 0x6);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, BIT(1), 0x0);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x54, 0x38000, 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x1c000, 0x0);
	odm_set_bb_reg(dm, 0x1b18, BIT(0), 0x0);
	odm_set_bb_reg(dm, 0x1b1c, BIT(1) | BIT(0), 0x2);
	odm_set_bb_reg(dm, 0x1b20, 0xfffff, 0x40008);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x018);
	odm_set_bb_reg(dm, 0x1bcc, 0x3f, 0x9);
	odm_set_bb_reg(dm, 0x1bcc, BIT(31), 0x1);
}

void _iqk_lok_for_rxk_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
	_iqk_cal_path_off_8197g(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);	
	odm_set_bb_reg(dm, 0x1b20, BIT(31) | BIT(30), 0x0);



	//LOK_RES Table
	if (*dm->band_type == ODM_BAND_2_4G) {
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0xf0000, 0x7);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(5), 0x1);		
		odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(10), 0x1);
		odm_set_bb_reg(dm, 0x1b20, 0x3e0, 0x12);// 12dB
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 020);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x18, BIT(16), 0x0);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, BIT(0), 0x0);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0x70, 0x4);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x0);		
	} else {
		odm_set_rf_reg(dm, (enum rf_path)path, 0x00, 0xf0000, 0x7);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(5), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x9e, BIT(10), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x000);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x18, BIT(16), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, BIT(0), 0x1);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x08, 0x70, 0x4);		
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(2), 0x0);
	}	
		odm_set_rf_reg(dm, (enum rf_path)path, 0x57, BIT(0), 0x0);
	
	//TX_LOK
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
	if (*dm->band_type == ODM_BAND_2_4G) {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x00);
		odm_write_1byte(dm, 0x1bcc, 0x09);		
		odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x38);
	} else {
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x20);
		odm_write_1byte(dm, 0x1bcc, 0x09);
		odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x38);
	}
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1); //LOK _Write_en
	odm_write_1byte(dm, 0x1b10, 0x0);		
	odm_write_1byte(dm, 0x1bcc, 0x12);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x038);
}

//static u8 wlg_lna[5] = {0x0, 0x1, 0x2, 0x3, 0x5};
//static u8 wla_lna[5] = {0x0, 0x1, 0x3, 0x4, 0x5};
void _iqk_rxk1_setting_8197g(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	_iqk_cal_path_off_8197g(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, 0xc, 0x3);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0x1fff, 0x40);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0xe000, 0x6);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, BIT(1), 0x0);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x54, 0x38000, 0x0);
	odm_set_bb_reg(dm, 0x1b18, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0x1b1c, BIT(1) | BIT(0), 0x2);
	odm_set_bb_reg(dm, 0x1b20, 0xfffff, 0x60008);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x018);
	odm_set_bb_reg(dm, 0x1bcc, 0x3f, 0x9);
	odm_set_bb_reg(dm, 0x1bcc, BIT(31), 0x1);
}

void _iqk_rxk2_setting_8197g(
	struct dm_struct *dm,
	u8 path,
	boolean is_gs)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	_iqk_cal_path_off_8197g(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xde, 0xc, 0x3);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0x1fff, 0x40);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, 0xe000, 0x6);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x8f, BIT(1), 0x0);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x54, 0x38000, 0x0);
	odm_set_bb_reg(dm, 0x1bcc, 0x3f, 0x9);
	odm_set_bb_reg(dm, 0x1b18, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0x1b18, BIT(1), 0x1);	
	odm_set_bb_reg(dm, 0x1b1c, BIT(1) | BIT(0), 0x1);
	odm_set_bb_reg(dm, 0x1b24, 0xfffff, 0x71008);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x018);
	odm_set_bb_reg(dm, 0x1bcc, BIT(30), 0x1);
	odm_set_bb_reg(dm, 0x1b1c, BIT(29), 0x1);
}

boolean
_iqk_check_cal_8197g(
	struct dm_struct *dm,
	u8 path,
	u8 cmd)
{
	boolean notready = true, fail = true;
	u32 delay_count = 0x0;

	while (notready) {
		if (odm_read_1byte(dm, 0x2d9c) == 0x55) {
			if (cmd == 0x0) /*LOK*/
				fail = false;
			else
				fail = (boolean)odm_get_bb_reg(dm, R_0x1b08, BIT(26));
			notready = false;
		} else {
			ODM_delay_ms(1);
			delay_count++;
		}

		if (delay_count >= 50) {
			fail = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]IQK timeout!!!\n");
			break;
		}
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = 0x%x!!!\n", delay_count);
	//return fail;	
	return false;
}

void
_iqk_set_lok_lut_8197g(
	struct dm_struct *dm,
	u8 path)
{
#if 0
	u32 temp;
	u8 idac_i, idac_q;
	u8 i;

	temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]setlut_0x58 = 0x%x\n", temp);
	idac_i = (u8)((temp & 0xfc000) >> 14);
	idac_q = (u8)((temp & 0x3f0) >> 4);
	temp =  (idac_i << 6) | idac_q;
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
	for (i = 0; i < 8; i++) {
		temp = (i << 14) | (temp & 0xfff);
		if (*dm->band_type == ODM_BAND_2_4G)
			odm_set_rf_reg(dm, (enum rf_path)path, 0x33, 0xfffff, temp);
		else
			odm_set_rf_reg(dm, (enum rf_path)path, 0x33, 0xfffff, 0x20 | temp);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]path =%d,0x33  = 0x%x!!!\n", path, temp);
	}
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);
#endif
}

boolean
_iqk_rx_iqk_gain_search_fail_8197g(
	struct dm_struct *dm,
	u8 path,
	u8 step)
{


	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true, k2fail = true;
	u32 IQK_CMD = 0x0, rf_reg0 = 0x0, tmp = 0x0, bb_idx = 0x0;
	u8 IQMUX[4] = {0x9, 0x12, 0x1b, 0x24};
	u8 idx;

	if (step == RXIQK1) {
		RF_DBG(dm, DBG_RF_IQK,
	       	       "[IQK]============ S%d RXIQK GainSearch ============\n",
	       	       path);
		IQK_CMD = 0x00000208 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
	       	       step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(1);
		fail = _iqk_check_cal_8197g(dm, path, 0x1);
	} else if (step == RXIQK2) {
		for (idx = 0; idx < 4; idx++) {
			if (iqk->tmp1bcc == IQMUX[idx])
				break;
		}
		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	
		odm_write_4byte(dm, 0x1bcc, iqk->tmp1bcc);

		IQK_CMD = 0x00000308 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger = 0x%x\n", path,
		       step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(2);
		k2fail = _iqk_check_cal_8197g(dm, path, 0x1);

		if (k2fail == true) {
			iqk->tmp1bcc = IQMUX[idx++];
			return true;
		}

		rf_reg0 = odm_get_rf_reg(dm, (enum rf_path)path,
					 RF_0x0, MASK20BITS);
		odm_write_4byte(dm, 0x1b00, 0x00000008 | path << 1);
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]S%d (0) RF0x0=0x%x tmp1bcc=0x%x idx=%d 0x1b3c=0x%x\n",
		       path, rf_reg0, iqk->tmp1bcc, idx,
		       odm_read_4byte(dm, 0x1b3c));
		
		tmp = (rf_reg0 & 0x1fe0) >> 5;
		iqk->lna_idx = tmp >> 5; // lna value
		bb_idx = tmp & 0x1f;
		if (bb_idx <= 0x1) {
			if (idx != 3)
				idx++;
			else
				iqk->isbnd = true;
			fail = true;
		} else if (bb_idx >= 0xa) {
			if (idx != 0)
				idx--;
			else
				iqk->isbnd = true;
			fail = true;
		} else {
			fail = false;
			iqk->isbnd = false;
		}
		
		if (iqk->isbnd)
			fail = false;
		
		iqk->tmp1bcc = IQMUX[idx];

		if (fail == false){
			tmp = iqk->tmp1bcc << 8 |  bb_idx ;
			odm_write_4byte(dm, 0x1be8, tmp);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d 0x1be8 = %x\n",path, tmp);
		}
#if 0
	if (bb_idx <= 0x1) {
		if (iqk->lna_idx != 0x0)
			iqk->lna_idx--;
		else if (idx != 3)
			idx++;
		else
			iqk->isbnd = true;
		fail = true;
	} else if (bb_idx >= 0xa) {
		if (idx != 0)
			idx--;
		else if (iqk->lna_idx != 0x7)
			iqk->lna_idx++;
		else
			iqk->isbnd = true;
		fail = true;
	} else {
		fail = false;
	}

	if (iqk->isbnd)
		fail = false;

	iqk->tmp1bcc = IQMUX[idx];

	RF_DBG(dm, DBG_RF_IQK,
	       "[IQK]S%d RF0x0=0x%x, tmp1bcc=0x%x, idx=%d,lna_idx=%d,bb_idx =%d \n",
	       path, rf_reg0, iqk->tmp1bcc, idx,iqk->lna_idx, bb_idx);

	if (fail) {
		odm_write_4byte(dm, 0x1b00, 0xf8000008 | path << 1);
		tmp = (odm_read_4byte(dm, 0x1b24) & 0xffffe3ff) |
			(iqk->lna_idx << 10);
		odm_write_4byte(dm, 0x1b24, tmp);
	}
#endif
}
	
return fail;

	
}

boolean
_lok_check_8197g(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	u32 temp;
	u8 idac_i, idac_q;
	u8 i;

	_iqk_cal_path_off_8197g(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);	

	temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
	//RF_DBG(dm, DBG_RF_IQK, "[IQK](1)setlut_0x58 = 0x%x\n", temp);
	idac_i = (u8)((temp & 0xfc000) >> 14);
	idac_q = (u8)((temp & 0x3f00) >> 8);

	if (!(idac_i == 0x0 || idac_i == 0x3f || idac_q == 0x0 || idac_q == 0x3f)) {		
		RF_DBG(dm, DBG_RF_IQK, "[IQK]LOK 0x58 = 0x%x\n", temp);
		return false;
	}

	idac_i = 0x20;
	idac_q = 0x20;

	odm_set_rf_reg(dm, (enum rf_path)path, 0x57, BIT(0), 0x0);	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);

	if (*dm->band_type == ODM_BAND_2_4G)
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x0);
	else
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x33, 0x7f, 0x20);

	//_iqk_rf_direct_access_8197g(dm, (enum rf_path)path, false);

	odm_set_rf_reg(dm, (enum rf_path)path, 0x08, 0x003f0, idac_i);
	odm_set_rf_reg(dm, (enum rf_path)path, 0x08, 0xfc000, idac_q);
	
	temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x08, 0xfffff);
	RF_DBG(dm, DBG_RF_IQK, "[IQK](2)setlut_0x08 = 0x%x\n", temp);
	
	temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
	RF_DBG(dm, DBG_RF_IQK, "[IQK](2)setlut_0x58 = 0x%x\n", temp);

	//_iqk_rf_direct_access_8197g(dm, (enum rf_path)path, true);
	
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);

	return true;

}


boolean
_lok_one_shot_8197g(
	void *dm_void,
	u8 path,
	boolean for_rxk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;

	u8 delay_count = 0;
	boolean LOK_notready = false;
	u32 temp = 0;
	u32 IQK_CMD = 0x0;
	u8 idac_i, idac_q;

	
	if (for_rxk) {
		RF_DBG(dm, DBG_RF_IQK,
			"[IQK]======S%d LOK for RXK======\n", path);
		IQK_CMD = 0x8 | (1 << (4 + path)) | (path << 1);
	} else { 
		RF_DBG(dm, DBG_RF_IQK,
			"[IQK]======S%d LOK======\n", path);
		IQK_CMD = 0x8 | (1 << (4 + path)) | (path << 1);
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]LOK_Trigger = 0x%x\n", IQK_CMD);
	_iqk_set_gnt_wl_gnt_bt_8197g(dm, true);
	_iqk_rf_direct_access_8197g(dm, (enum rf_path)path, false);
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 1);	
	ODM_delay_ms(IQK_DELAY_8197G);
	_iqk_rf_direct_access_8197g(dm, (enum rf_path)path, true);
	/*LOK: CMD ID = 0	{0xf8000018, 0xf8000028}*/
	/*LOK: CMD ID = 0	{0xf8000019, 0xf8000029}*/

	// idx of LOK LUT table, EF[4]:WE_LUT_TX_LOK
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);

	LOK_notready = _iqk_check_cal_8197g(dm, path, 0x0);
	_iqk_set_gnt_wl_gnt_bt_8197g(dm, false);
	if(!for_rxk)
		iqk->rf_reg58 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);

	if (!LOK_notready)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]0x58 = 0x%x\n",
		       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff));
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]==>S%d LOK Fail!!!\n", path);
	iqk->lok_fail[path] = LOK_notready;
	return LOK_notready;
}

boolean
_iqk_check_txk_8197g(struct dm_struct *dm, u8 path, u8 idx)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean ready = false, fail = false;
	u32 delay_count = 0x0;
	u32 iq_x, iq_y, temp = 0x0;
	u32 ex_bp = 0, bp = 0;
	/*cmd=0:TXIQK, 1:RXIQK*/
#if 1
	while (delay_count < 100) {
		delay_count++;
		ODM_delay_ms(1);
		odm_write_4byte(dm, 0x1bd4, 0x001d0001);
		if (odm_get_bb_reg(dm, 0x1bfc, BIT(1))) {
			ready = true;
			break;
		}
	}
	odm_set_bb_reg(dm, 0x1bcc, BIT(31), 0x0);
	if (idx == TXIQK)
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);
#endif
	odm_write_4byte(dm, 0x1bd4, 0x00150001);
	temp = odm_get_bb_reg(dm, 0x1bfc, MASKDWORD);
	iq_x = (temp & 0x7ff0000) >> 16;
	iq_y = temp & 0x7ff;
	RF_DBG(dm, DBG_RF_IQK, "[IQK]iq_x = 0x%x, iq_y = 0x%x\n", iq_x, iq_y);
	/*monitor image power before & after IQK*/
	odm_write_4byte(dm, 0x1bd4, 0x00180001);
	bp =  odm_get_bb_reg(dm, 0x1bfc, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]before= 0x%x\n", bp);
	odm_write_4byte(dm, 0x1bd4, 0x00190001);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]after= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, MASKDWORD));
	odm_write_4byte(dm, 0x1bd4, 0x00170001);
	ex_bp = odm_get_bb_reg(dm, 0x1bfc, 0x1f0000);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]extend_b= 0x%x\n", ex_bp);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]extend_a= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, 0x1f));

	odm_write_4byte(dm, 0x1bd4, 0x001d0001);
		if (odm_get_bb_reg(dm, 0x1bfc, BIT(3))) {
			if (bp < 0x10000 && ex_bp == 0x0)
				RF_DBG(dm, DBG_RF_IQK,"[IQK]default is not bad!!!!\n");
			else
			fail = true;
		}
	RF_DBG(dm, DBG_RF_IQK, "[IQK] fail = %d\n", fail);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = 0x%x!!\n", delay_count);

	if ((!fail) && (idx == TXIQK)) {
		iqk->txxy[path][0] = iq_x;
		iqk->txxy[path][1] = iq_y;
	}

	if ((!fail) && (idx == RXIQK1)) {
		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		temp = (iq_x << 20) | (iq_y << 8);
		odm_write_4byte(dm, 0x1b38, temp);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1b38= 0x%x!!\n", temp);
	}	
	
	return fail;
}

boolean
_iqk_check_rxk_8197g(struct dm_struct *dm, u8 path)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean ready = false, fail = false;
	u32 delay_count = 0x0;
	u32 iq_x, iq_y, temp = 0x0;
	/*cmd=0:TXIQK, 1:RXIQK*/
#if 1
	while (delay_count < 100) {
		delay_count++;
		ODM_delay_ms(1);
		odm_write_4byte(dm, 0x1bd4, 0x001d0001);
		if (odm_get_bb_reg(dm, 0x1bfc, BIT(1))) {
			ready = true;
			break;
		}
	}
	odm_set_bb_reg(dm, 0x1bcc, BIT(30), 0x0);	
#endif
	odm_write_4byte(dm, 0x1bd4, 0x00160001);
	temp = odm_get_bb_reg(dm, 0x1bfc, MASKDWORD);
	iq_x = (temp & 0x7ff0000) >> 16;
	iq_y = temp & 0x7ff;
	RF_DBG(dm, DBG_RF_IQK, "[IQK]iq_x = 0x%x, iq_y = 0x%x\n", iq_x, iq_y);
	/*monitor image power before & after IQK*/
	odm_write_4byte(dm, 0x1bd4, 0x001b0001);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]before= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, MASKDWORD));
	odm_write_4byte(dm, 0x1bd4, 0x001c0001);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]after= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, MASKDWORD));
	odm_write_4byte(dm, 0x1bd4, 0x001a0001);
	RF_DBG(dm, DBG_RF_IQK,"[IQK]extend_b= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, 0x1f0000));
	RF_DBG(dm, DBG_RF_IQK,"[IQK]extend_a= 0x%x\n", odm_get_bb_reg(dm, 0x1bfc, 0x1f));

	odm_write_4byte(dm, 0x1bd4, 0x001d0001);
		if (odm_get_bb_reg(dm, 0x1bfc, BIT(2)))
			fail = true;
	RF_DBG(dm, DBG_RF_IQK, "[IQK]fail = %d\n", fail);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = 0x%x!!\n", delay_count);

	if (!fail) {
		iqk->rxxy[path][0] = iq_x;
		iqk->rxxy[path][1] = iq_y;
	}
	return fail;
}

boolean
_iqk_one_shot_8197g(void *dm_void, u8 path, u8 idx)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 delay_count = 0;
	boolean fail = true;
	u32 IQK_CMD = 0x0, tmp;

	if (idx == TXIQK)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d TXIQK ============\n", path);
	else if (idx == RXIQK1)
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============ S%d RXIQK1============\n", path);
	else
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK]============S%d RXIQK2============\n", path);

	odm_set_bb_reg(dm, 0x1b34, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0x1b34, BIT(0), 0x0);

	ODM_delay_ms(IQK_DELAY_8197G);
	if (idx == TXIQK || idx == RXIQK1)
		fail = _iqk_check_txk_8197g(dm, path, idx);
	else
		fail = _iqk_check_rxk_8197g(dm, path);		

	if (idx == RXIQK2) {
		RF_DBG(dm, DBG_RF_IQK,"[IQK]RF0x0 = 0x%x, RF0x56 = 0x%x\n",
		       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x0, MASK20BITS),
		       odm_get_rf_reg(dm, (enum rf_path)path, RF_0x56, MASK20BITS));
	}

	if (idx == TXIQK)
		iqk->iqk_fail_report[0][path][TXIQK] = fail;
	else
		iqk->iqk_fail_report[0][path][RXIQK] = fail;
	return fail;
}


boolean
_iqk_rx_iqk_by_path_8197g(
	void *dm_void,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = false, gonext;
	u32 tmp;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]rx_iqk_step = 0x%x\n", iqk->rxiqk_step);

#if 1
	switch (iqk->rxiqk_step) {
	case 0: //LOK for RXK 
#if 0
		_iqk_lok_for_rxk_setting_8197g(dm, path);
		_lok_one_shot_8197g(dm, path, true);
#endif
		iqk->rxiqk_step++;
		break;
	case 1: /*gain search_RXK1*/
#if 0
		_iqk_rxk1_setting_8197g(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_rx_iqk_gain_search_fail_8197g(dm, path, RXIQK1);
			if (KFAIL && iqk->gs_retry_count[0][path][0] < 2)
				iqk->gs_retry_count[0][path][0]++;
			else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 0;
				iqk->rxiqk_step = RXK_STEP_8197G;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
		//halrf_iqk_xym_read(dm, path, 0x2);
#else
		iqk->rxiqk_step++;
#endif
		break;
	case 2: /*RXK1*/
#if 1
		_iqk_rxk1_setting_8197g(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8197g(dm, path, RXIQK1);			
			if (KFAIL && iqk->retry_count[0][path][RXIQK1] < 2)
				iqk->retry_count[0][path][RXIQK1]++;
			else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 1;
				iqk->rxiqk_step = RXK_STEP_8197G;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
#else
		iqk->rxiqk_step++;
#endif
			break;

	case 3: /*gain search_RXK2*/
#if 0
		_iqk_rxk2_setting_8197g(dm, path, true);
		iqk->isbnd = false;
		while (1) {
			RF_DBG(dm, DBG_RF_IQK, "[IQK]gs2_retry = %d\n", iqk->gs_retry_count[0][path][1]);
			KFAIL = _iqk_rx_iqk_gain_search_fail_8197g(dm, path, RXIQK2);
			if (KFAIL && (iqk->gs_retry_count[0][path][1] < rxiqk_gs_limit))
				iqk->gs_retry_count[0][path][1]++;
			else {
				iqk->rxiqk_step++;
				break;
			}
		}
		//halrf_iqk_xym_read(dm, path, 0x3);
#else
		iqk->rxiqk_step++;
#endif
		break;
	case 4: /*RXK2*/
#if 1
		_iqk_rxk2_setting_8197g(dm, path, false);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8197g(dm, path, RXIQK2);			
			if (KFAIL && iqk->retry_count[0][path][RXIQK2] < 2)
				iqk->retry_count[0][path][RXIQK2]++;
			else if (KFAIL) {
				iqk->rxiqk_fail_code[0][path] = 2;
				iqk->rxiqk_step = RXK_STEP_8197G;
				gonext = true;
			} else {
				iqk->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
#else
	iqk->rxiqk_step++;
#endif
		break;
	case 5: /*restore TXLOK*/
#if 0
		_iqk_reload_lok_setting_8197g(dm, path);
		iqk->rxiqk_step++;
#else
		iqk->rxiqk_step++;
#endif
		break;

	}
	return KFAIL;
#endif
}

void
_iqk_update_txiqc_8197g(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 temp = 0x0;

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	temp = (iqk->txxy[path][0] << 20) | (iqk->txxy[path][1] << 8);
	odm_write_4byte(dm, 0x1b38, temp);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]update S%d 0x1b38 = 0x%x\n", path,
	       odm_get_bb_reg(dm, 0x1b38, MASKDWORD));
}

void
_iqk_update_rxiqc_8197g(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 temp = 0x0;

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	temp = (iqk->rxxy[path][0] << 20) | (iqk->rxxy[path][1] << 8);
	odm_write_4byte(dm, 0x1b3c, temp);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]update S%d 0x1b3c = 0x%x\n", path,
	       odm_get_bb_reg(dm, 0x1b3c, MASKDWORD));
}

void
_iqk_udpate_iqc_8197g(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i;

	for (i = 0; i < SS_8197G; i++) {
		if(iqk->iqk_fail_report[0][i][0] == false)
			_iqk_update_txiqc_8197g(dm, i);
		if(iqk->iqk_fail_report[0][i][1] == false)
			_iqk_update_rxiqc_8197g(dm, i);	
	}
}

void _iqk_iqk_by_path_8197g(
	void *dm_void,
	boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean KFAIL = true;
	u8 i, kcount_limit;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]iqk_step = 0x%x\n", iqk->iqk_step);
#if 1
	switch (iqk->iqk_step) {
	case 0: /*S0 TXIQK*/
		_iqk_txk_setting_8197g(dm, RF_PATH_A);
		KFAIL = _iqk_one_shot_8197g(dm, RF_PATH_A, TXIQK);
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0TXK KFail = 0x%x\n", KFAIL);
		iqk->iqk_step++;
#else
		iqk->iqk_step++;
#endif
	break;

	case 1: /*S0 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8197g(dm, RF_PATH_A);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S0RXK KFail = 0x%x\n", KFAIL);
			if (iqk->rxiqk_step == RXK_STEP_8197G) {
				iqk->iqk_step++;
				iqk->rxiqk_step = 0;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S0RXK fail code: %d!!!\n", iqk->rxiqk_fail_code[0][RF_PATH_A]);
				break;
			}
		}
		iqk->kcount++;		
#else
		iqk->iqk_step++;
#endif
		break;
	case 2: /*S1 TXIQK*/
#if 1
		_iqk_txk_setting_8197g(dm, RF_PATH_B);
		KFAIL = _iqk_one_shot_8197g(dm, RF_PATH_B, TXIQK);
//		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, BIT(4), 0x0);
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S1TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_B][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_B][TXIQK]++;
		else
			iqk->iqk_step++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]iqk->iqk_step = 0x%x\n", iqk->iqk_step);
#else
			iqk->iqk_step++;
#endif
		break;
	case 3: /*S1 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8197g(dm, RF_PATH_B);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S1RXK KFail = 0x%x\n", KFAIL);
			if (iqk->rxiqk_step == RXK_STEP_8197G) {
				iqk->iqk_step++;
				iqk->rxiqk_step = 0;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S1RXK fail code: %d!!!\n", iqk->rxiqk_fail_code[0][RF_PATH_B]);
				break;
			}
		}
		iqk->kcount++;		
#else
		iqk->iqk_step++;
#endif
		break;

	case 4: /*S1 LOK*/
#if 0
		_iqk_lok_setting_8197g(dm, RF_PATH_B);
		_lok_one_shot_8197g(dm, RF_PATH_B, false);		
		if(_lok_check_8197g(dm, RF_PATH_B))	
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S1 Load LOK to default\n");
#endif
		iqk->iqk_step++;
		break;
	
	case 5: /*S1 TXIQK*/
#if 0
		_iqk_txk_setting_8197g(dm, RF_PATH_B);
		KFAIL = _iqk_one_shot_8197g(dm, RF_PATH_B, TXIQK);
//		odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, BIT(4), 0x0);
		iqk->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S1TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk->retry_count[0][RF_PATH_B][TXIQK] < 3)
			iqk->retry_count[0][RF_PATH_B][TXIQK]++;
		else
			iqk->iqk_step++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]iqk->iqk_step = 0x%x\n", iqk->iqk_step);
#else
				iqk->iqk_step++;
#endif
		break;
	case 6: /*update IQC*/
#if 1
		_iqk_udpate_iqc_8197g(dm);
		iqk->iqk_step++;
#else
	iqk->iqk_step++;
#endif
		break;
	}

	if (iqk->iqk_step == IQK_STEP_8197G) {
		RF_DBG(dm, DBG_RF_IQK, "[IQK]========LOK summary =========\n");
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_LOK_fail= %d, S1_LOK_fail= %d\n",
		       iqk->lok_fail[RF_PATH_A],
		       iqk->lok_fail[RF_PATH_B]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]========IQK summary ==========\n");
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXIQK_fail = %d, S1_TXIQK_fail = %d\n"
		       ,iqk->iqk_fail_report[0][RF_PATH_A][TXIQK],
		       iqk->iqk_fail_report[0][RF_PATH_B][TXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXIQK_fail= %d, S1_RXIQK_fail= %d\n"
		       ,iqk->iqk_fail_report[0][RF_PATH_A][RXIQK],
		       iqk->iqk_fail_report[0][RF_PATH_B][RXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TK_retry = %d, S1_TXIQK_retry = %d\n"
		       ,iqk->retry_count[0][RF_PATH_A][TXIQK],
		       iqk->retry_count[0][RF_PATH_B][TXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK1_retry = %d, S0_RXK2_retry = %d\n"
		       ,iqk->retry_count[0][RF_PATH_A][RXIQK1], 
		       iqk->retry_count[0][RF_PATH_A][RXIQK2]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_RXK1_retry = %d, S2_RXK2_retry = %d\n"
		       ,iqk->retry_count[0][RF_PATH_B][RXIQK1],
		       iqk->retry_count[0][RF_PATH_B][RXIQK2]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_GS1_retry = %d, S0_GS2_retry = %d, S1_GS1_retry = %d, S1_GS2_retry = %d\n"
		       ,iqk->gs_retry_count[0][RF_PATH_A][0],
		       iqk->gs_retry_count[0][RF_PATH_A][1],
		       iqk->gs_retry_count[0][RF_PATH_B][0],
		       iqk->gs_retry_count[0][RF_PATH_B][1]);

		for (i = 0; i < SS_8197G; i++) {
			odm_write_4byte(dm, 0x1b00, 0x8 | i << 1);
			//odm_set_bb_reg(dm, 0x1b20, BIT(26), 0x1);
			odm_write_1byte(dm, 0x1bcc, 0x0);
			//odm_write_4byte(dm, 0x1b38, 0x20000000);
			//odm_write_4byte(dm, 0x1b38, 0x40000000);
		}
	}
}

void _iqk_start_iqk_8197g(
	struct dm_struct *dm,
	boolean segment_iqk)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i = 0;
	u8 kcount_limit;
	
	if (*dm->band_width == 2)
		kcount_limit = kcount_limit_80m;
	else
		kcount_limit = kcount_limit_others;

	while (i <  100) {
		_iqk_iqk_by_path_8197g(dm, segment_iqk);
		if (iqk->iqk_step == IQK_STEP_8197G)
			break;
		if (segment_iqk && (iqk->kcount == kcount_limit))
			break;
		i++;
	}
}

void _iq_calibrate_8197g_init(
	struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u8 i, j, k, m;
	static boolean firstrun = true;

	if (firstrun) {
		firstrun = false;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]=====>PHY_IQCalibrate_8197g_Init\n");

		for (i = 0; i < SS_8197G; i++) {
			for (j = 0; j < 2; j++) {
				iqk->lok_fail[i] = true;
				iqk->iqk_fail[j][i] = true;
				iqk->iqc_matrix[j][i] = 0x20000000;
			}
		}

		for (i = 0; i < 2; i++) {
			iqk->iqk_channel[i] = 0x0;

			for (j = 0; j < SS_8197G; j++) {
				iqk->lok_idac[i][j] = 0x0;
				iqk->rxiqk_agc[i][j] = 0x0;
				iqk->bypass_iqk[i][j] = 0x0;

				for (k = 0; k < 2; k++) {
					iqk->iqk_fail_report[i][j][k] = true;
					for (m = 0; m < 8; m++) {
						iqk->iqk_cfir_real[i][j][k][m] = 0x0;
						iqk->iqk_cfir_imag[i][j][k][m] = 0x0;
					}
				}

				for (k = 0; k < 3; k++)
					iqk->retry_count[i][j][k] = 0x0;
			}
		}
	}

}

boolean
_iqk_rximr_rxk1_test_8197g(
	struct dm_struct *dm,
	u8 path,
	u32 tone_index)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD;

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1b20, (odm_read_4byte(dm, 0x1b20) & 0x000fffff) | ((tone_index & 0xfff) << 20));
	odm_write_4byte(dm, 0x1b24, (odm_read_4byte(dm, 0x1b24) & 0x000fffff) | ((tone_index & 0xfff) << 20));

	IQK_CMD = 0xf8000208 | (1 << (path + 4));
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);

	ODM_delay_ms(IQK_DELAY_8197G);
	fail = _iqk_check_cal_8197g(dm, path, 0x1);
	return fail;
}

u32 _iqk_tximr_selfcheck_8197g(
	void *dm_void,
	u8 tone_index,
	u8 path)
{
	u32 tx_ini_power_H[2], tx_ini_power_L[2];
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD;
	u32 tximr = 0x0;
	u8 i;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	/*backup*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1bc8, 0x80000000);
	odm_write_4byte(dm, 0x8f8, 0x41400080);
	tmp1 = odm_read_4byte(dm, 0x1b0c);
	tmp2 = odm_read_4byte(dm, 0x1b14);
	tmp3 = odm_read_4byte(dm, 0x1b1c);
	tmp4 = odm_read_4byte(dm, 0x1b20);
	tmp5 = odm_read_4byte(dm, 0x1b24);
	/*setup*/
	odm_write_4byte(dm, 0x1b0c, 0x00003000);
	odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
	odm_write_1byte(dm, 0x1b15, 0x00);
	odm_write_4byte(dm, 0x1b20, (u32)(tone_index << 20 | 0x00040008));
	odm_write_4byte(dm, 0x1b24, (u32)(tone_index << 20 | 0x00060008));
	odm_write_4byte(dm, 0x1b2c, 0x07);
	odm_write_4byte(dm, 0x1b38, 0x40000000);
	odm_write_4byte(dm, 0x1b3c, 0x40000000);
	/* ======derive pwr1========*/
	for (i = 0; i < SS_8197G; i++) {
		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		if (i == 0)
			odm_write_1byte(dm, 0x1bcc, 0x0f);
		else
			odm_write_1byte(dm, 0x1bcc, 0x09);
		/* One Shot*/
		IQK_CMD = 0x00000800;
		odm_write_4byte(dm, 0x1b34, IQK_CMD + 1);
		odm_write_4byte(dm, 0x1b34, IQK_CMD);
		ODM_delay_ms(1);
		odm_write_4byte(dm, 0x1bd4, 0x00040001);
		tx_ini_power_H[i] = odm_read_4byte(dm, 0x1bfc);
		odm_write_4byte(dm, 0x1bd4, 0x000C0001);
		tx_ini_power_L[i] = odm_read_4byte(dm, 0x1bfc);
	}
	/*restore*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1b0c, tmp1);
	odm_write_4byte(dm, 0x1b14, tmp2);
	odm_write_4byte(dm, 0x1b1c, tmp3);
	odm_write_4byte(dm, 0x1b20, tmp4);
	odm_write_4byte(dm, 0x1b24, tmp5);

	if (tx_ini_power_H[1] == tx_ini_power_H[0])
		tximr = (3 * (halrf_psd_log2base(tx_ini_power_L[0] << 2) - halrf_psd_log2base(tx_ini_power_L[1]))) / 100;
	else
		tximr = 0;
	return tximr;
}

void _iqk_start_tximr_test_8197g(
	struct dm_struct *dm,
	u8 imr_limit)
{
	boolean KFAIL;
	u8 path, i, tone_index;
	u32 imr_result;

	for (path = 0; path < SS_8197G; path++) {
		_iqk_txk_setting_8197g(dm, path);
		KFAIL = _iqk_one_shot_8197g(dm, path, TXIQK);
		for (i = 0x0; i < imr_limit; i++) {
			tone_index = (u8)(0x08 | i << 4);
			imr_result = _iqk_tximr_selfcheck_8197g(dm, tone_index, path);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]path=%x, toneindex = %x, TXIMR = %d\n", path, tone_index, imr_result);
		}
		RF_DBG(dm, DBG_RF_IQK, "\n");
	}
}

u32 _iqk_rximr_selfcheck_8197g(
	void *dm_void,
	u32 tone_index,
	u8 path,
	u32 tmp1b38)
{
	u32 rx_ini_power_H[2], rx_ini_power_L[2]; /*[0]: psd tone; [1]: image tone*/
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD, tmp1bcc;
	u8 i, num_k1, rximr_step, count = 0x0;
	u32 rximr = 0x0;
	boolean KFAIL = true;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	/*backup*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	tmp1 = odm_read_4byte(dm, 0x1b0c);
	tmp2 = odm_read_4byte(dm, 0x1b14);
	tmp3 = odm_read_4byte(dm, 0x1b1c);
	tmp4 = odm_read_4byte(dm, 0x1b20);
	tmp5 = odm_read_4byte(dm, 0x1b24);

	odm_write_4byte(dm, 0x1b0c, 0x00001000);
	odm_write_1byte(dm, 0x1b15, 0x00);
	odm_write_4byte(dm, 0x1b1c, 0x82193d31);
	odm_write_4byte(dm, 0x1b20, (u32)(tone_index << 20 | 0x00040008));
	odm_write_4byte(dm, 0x1b24, (u32)(tone_index << 20 | 0x00060048));
	odm_write_4byte(dm, 0x1b2c, 0x07);
	odm_write_4byte(dm, 0x1b38, tmp1b38);
	odm_write_4byte(dm, 0x1b3c, 0x40000000);

	for (i = 0; i < 2; i++) {
		if (i == 0)
			odm_write_4byte(dm, 0x1b1c, 0x82193d31);
		else
			odm_write_4byte(dm, 0x1b1c, 0xa2193d31);
		IQK_CMD = 0x00000800;
		odm_write_4byte(dm, 0x1b34, IQK_CMD + 1);
		odm_write_4byte(dm, 0x1b34, IQK_CMD);
		ODM_delay_ms(2);
		odm_write_1byte(dm, 0x1bd6, 0xb);
		while (count < 100) {
			count++;
			if (odm_get_bb_reg(dm, R_0x1bfc, BIT(1)) == 1)
				break;
			else
				ODM_delay_ms(1);
		}
		if (1) {
			odm_write_1byte(dm, 0x1bd6, 0x5);
			rx_ini_power_H[i] = odm_read_4byte(dm, 0x1bfc);
			odm_write_1byte(dm, 0x1bd6, 0xe);
			rx_ini_power_L[i] = odm_read_4byte(dm, 0x1bfc);
		} else {
			rx_ini_power_H[i] = 0x0;
			rx_ini_power_L[i] = 0x0;
		}
	}
	/*restore*/
	odm_write_4byte(dm, 0x1b0c, tmp1);
	odm_write_4byte(dm, 0x1b14, tmp2);
	odm_write_4byte(dm, 0x1b1c, tmp3);
	odm_write_4byte(dm, 0x1b20, tmp4);
	odm_write_4byte(dm, 0x1b24, tmp5);
	for (i = 0; i < 2; i++)
		rx_ini_power_H[i] = (rx_ini_power_H[i] & 0xf8000000) >> 27;

	if (rx_ini_power_H[0] != rx_ini_power_H[1])
		switch (rx_ini_power_H[0]) {
		case 1:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 1) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 1;
			break;
		case 2:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 2) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 3:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 2) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 4:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 5:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xa0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 6:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 7:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xe0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		default:
			break;
		}
	rximr = (u32)(3 * ((halrf_psd_log2base(rx_ini_power_L[0] / 100) - halrf_psd_log2base(rx_ini_power_L[1] / 100))) / 100);
	/*
		RF_DBG(dm, DBG_RF_IQK, "%-20s: 0x%x, 0x%x, 0x%x, 0x%x,0x%x, tone_index=%x, rximr= %d\n",
		(path == 0) ? "PATH A RXIMR ": "PATH B RXIMR",
		rx_ini_power_H[0], rx_ini_power_L[0], rx_ini_power_H[1], rx_ini_power_L[1], tmp1bcc, tone_index, rximr);
*/
	return rximr;
}

void _iqk_rximr_test_8197g(
	struct dm_struct *dm,
	u8 path,
	u8 imr_limit)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	boolean kfail;
	u8 i, step, count, side;
	u32 imr_result = 0, tone_index;
	u32 temp = 0, temp1b38[2][15];
	char *freq[15] = {"1.25MHz", "3.75MHz", "6.25MHz", "8.75MHz", "11.25MHz",
			  "13.75MHz", "16.25MHz", "18.75MHz", "21.25MHz", "23.75MHz",
			  "26.25MHz", "28.75MHz", "31.25MHz", "33.75MHz", "36.25MHz"};

	for (step = 1; step < 5; step++) {
		count = 0;
		switch (step) {
		case 1: /*gain search_RXK1*/
			_iqk_rxk1_setting_8197g(dm, path);
			while (count < 3) {
				kfail = _iqk_rx_iqk_gain_search_fail_8197g(dm, path, RXIQK1);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
				if (kfail) {
					count++;
					if (count == 3)
						step = 5;
				} else {
					break;
				}
			}
			break;
		case 2: /*gain search_RXK2*/
			_iqk_rxk2_setting_8197g(dm, path, true);
			iqk->isbnd = false;
			while (count < 8) {
				kfail = _iqk_rx_iqk_gain_search_fail_8197g(dm, path, RXIQK2);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
				if (kfail) {
					count++;
					if (count == 8)
						step = 5;
				} else {
					break;
				}
			}
			break;
		case 3: /*get RXK1 IQC*/
			odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
			temp = odm_read_4byte(dm, 0x1b1c);
			for (side = 0; side < 2; side++) {
				for (i = 0; i < imr_limit; i++) {
					if (side == 0)
						tone_index = 0xff8 - (i << 4);
					else
						tone_index = 0x08 | (i << 4);
					while (count < 3) {
						_iqk_rxk1_setting_8197g(dm, path);
						kfail = _iqk_rximr_rxk1_test_8197g(dm, path, tone_index);
						RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
						if (kfail) {
							count++;
							if (count == 3) {
								step = 5;
								temp1b38[side][i] = 0x20000000;
								RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, toneindex = %x rxk1 fail\n", path, tone_index);
							}
						} else {
							odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
							odm_write_4byte(dm, 0x1b1c, 0xa2193c32);
							odm_write_4byte(dm, 0x1b14, 0xe5);
							odm_write_4byte(dm, 0x1b14, 0x0);
							temp1b38[side][i] = odm_read_4byte(dm, 0x1b38);
							RF_DBG(dm, DBG_RF_IQK, "[IQK]path = 0x%x, tone_idx = 0x%x, tmp1b38 = 0x%x\n", path, tone_index, temp1b38[side][i]);
							break;
						}
					}
				}
			}
			break;
		case 4: /*get RX IMR*/
			for (side = 0; side < 2; side++) {
				for (i = 0x0; i < imr_limit; i++) {
					if (side == 0)
						tone_index = 0xff8 - (i << 4);
					else
						tone_index = 0x08 | (i << 4);
					_iqk_rxk2_setting_8197g(dm, path, false);
					imr_result = _iqk_rximr_selfcheck_8197g(dm, tone_index, path, temp1b38[side][i]);
					RF_DBG(dm, DBG_RF_IQK, "[IQK]tone_idx = 0x%5x, freq = %s%10s, RXIMR = %5d dB\n", tone_index, (side == 0) ? "-" : " ", freq[i], imr_result);
				}
				odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
				odm_write_4byte(dm, 0x1b1c, temp);
				odm_write_4byte(dm, 0x1b38, 0x20000000);
			}
			break;
		}
	}
}

void _iqk_start_rximr_test_8197g(
	struct dm_struct *dm,
	u8 imr_limit)
{
	u8 path;

	for (path = 0; path < SS_8197G; path++)
		_iqk_rximr_test_8197g(dm, path, imr_limit);
}

void _iqk_start_imr_test_8197g(
	void *dm_void)
{
	u8 imr_limit;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (*dm->band_width == 2)
		imr_limit = 0xf;
	else if (*dm->band_width == 1)
		imr_limit = 0x8;
	else
		imr_limit = 0x4;
	//	_iqk_start_tximr_test_8197g(dm, imr_limit);
	_iqk_start_rximr_test_8197g(dm, imr_limit);
}



void _phy_iq_calibrate_8197g(
	struct dm_struct *dm,
	boolean reset,
	boolean segment_iqk)
{
	u32 MAC_backup[MAC_REG_NUM_8197G], BB_backup[BB_REG_NUM_8197G], RF_backup[RF_REG_NUM_8197G][SS_8197G];
	u32 backup_mac_reg[MAC_REG_NUM_8197G] = {0x520};
	u32 backup_bb_reg[BB_REG_NUM_8197G] = {0x180c,0x410c, 0x1c38, 0x1d58, 0x1864, 0x4164, 0x824, 0x1a00};
	u32 backup_rf_reg[RF_REG_NUM_8197G] = {0xde, 0x8f};
	u32 temp0, temp1;
	boolean is_mp = false;
	u8 i = 0;

	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (*dm->mp_mode)
		is_mp = true;
#if 0
	if (!is_mp)
		if (_iqk_reload_iqk_8197g(dm, reset))
			return;
#endif
	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK strat!!!!!==========\n");
	RF_DBG(dm, DBG_RF_IQK, "[IQK]band_type = %s, band_width = %d, ExtPA2G = %d, ext_pa_5g = %d\n", (*dm->band_type == ODM_BAND_5G) ? "5G" : "2G", *dm->band_width, dm->ext_pa, dm->ext_pa_5g);

	iqk->kcount = 0;
	iqk->iqk_step = 0;
	iqk->rxiqk_step = 0;


	odm_write_4byte(dm, 0x1b00, 0x8);
	temp0 = odm_read_4byte(dm, 0x1b38);
	odm_write_4byte(dm, 0x1b00, 0xa);
	temp1 = odm_read_4byte(dm, 0x1b38);

	_iqk_backup_iqk_8197g(dm, 0x0, 0x0);
	_iqk_backup_mac_bb_8197g(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_backup_rf_8197g(dm, RF_backup, backup_rf_reg);

	while (i < 3) {
		i++;
		_iqk_macbb_8197g(dm);		
		//odm_read_and_config_mp_8197g_cal_init(dm);
		//_iqk_rf_setting_8197g(dm);
		//_iqk_bb_for_dpk_setting_8197g(dm);
		_iqk_afe_setting_8197g(dm, true);
		//_iqk_rfe_setting_8197g(dm, false);
		_iqk_start_iqk_8197g(dm, segment_iqk);
		_iqk_afe_setting_8197g(dm, false);
		_iqk_restore_rf_8197g(dm, backup_rf_reg, RF_backup);
		_iqk_restore_mac_bb_8197g(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
		if (iqk->iqk_step == IQK_STEP_8197G)
			break;
		iqk->kcount = 0;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]delay 50ms!!!\n");
		ODM_delay_ms(50);
	};
//	_iqk_fill_iqk_report_8197g(dm, 0);
	if(iqk->iqk_fail_report[0][0][0] == true) {
		odm_write_4byte(dm, 0x1b00, 0x8);
		odm_write_4byte(dm, 0x1b38, temp0);
	}
	if(iqk->iqk_fail_report[0][1][0] == true) {
		odm_write_4byte(dm, 0x1b00, 0xa);
		odm_write_4byte(dm, 0x1b38, temp1);
	}

	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK end!!!!!==========\n");
}

void _phy_iq_calibrate_by_fw_8197g(
	void *dm_void,
	u8 clear,
	u8 segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk = &dm->IQK_info;
	enum hal_status status = HAL_STATUS_FAILURE;

	if (*dm->mp_mode)
		clear = 0x1;
	//	else if (dm->is_linked)
	//		segment_iqk = 0x1;

	iqk->iqk_times++;
	status = odm_iq_calibrate_by_fw(dm, clear, segment_iqk);

	if (status == HAL_STATUS_SUCCESS)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK OK!!!\n");
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK fail!!!\n");
}

void phy_iq_calibrate_8197g(
	void *dm_void,
	boolean clear,
	boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;

	if (!(rf->rf_supportability & HAL_RF_IQK))
		return;

	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, true);
	
	//if (!(*dm->mp_mode))
	//	_iqk_check_coex_status(dm, true);

	/*FW IQK*/
	if (dm->fw_offload_ability & PHYDM_RF_IQK_OFFLOAD) {
		_phy_iq_calibrate_by_fw_8197g(dm, clear, (u8)(segment_iqk));
		phydm_get_read_counter_8197g(dm);
		_iqk_check_if_reload(dm);
		//RF_DBG(dm, DBG_RF_IQK, "[IQK]0x38= 0x%x\n",
		//       _iqk_btc_read_indirect_reg_8197g(dm, 0x38));
	} else {
		_iq_calibrate_8197g_init(dm);
		_phy_iq_calibrate_8197g(dm, clear, segment_iqk);
	}
	_iqk_fail_count_8197g(dm);
	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, false);
#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	_iqk_iqk_fail_report_8197g(dm);
#endif
	halrf_iqk_dbg(dm);
}

void _phy_imr_measure_8197g(
	struct dm_struct *dm)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;
	u32 MAC_backup[MAC_REG_NUM_8197G], BB_backup[BB_REG_NUM_8197G], RF_backup[RF_REG_NUM_8197G][SS_8197G];
	u32 backup_mac_reg[MAC_REG_NUM_8197G] = {0x520, 0x550};
	u32 backup_bb_reg[BB_REG_NUM_8197G] = {0x820, 0x824, 0x1c38, 0x1c68, 0x1d60, 0x180c, 0x410c, 0x1c3c};
	u32 backup_rf_reg[RF_REG_NUM_8197G] = {0xdf, 0x0};

	_iqk_backup_iqk_8197g(dm, 0x0, 0x0);
	_iqk_backup_mac_bb_8197g(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_backup_rf_8197g(dm, RF_backup, backup_rf_reg);
	_iqk_macbb_8197g(dm);
	_iqk_afe_setting_8197g(dm, true);
	_iqk_rfe_setting_8197g(dm, false);
//	_iqk_agc_bnd_int_8197g(dm);
//	_iqk_rf_setting_8197g(dm);
	_iqk_start_imr_test_8197g(dm);
	_iqk_afe_setting_8197g(dm, false);
	_iqk_restore_mac_bb_8197g(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_restore_rf_8197g(dm, backup_rf_reg, RF_backup);
}

void do_imr_test_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]  ************IMR Test *****************\n");
	_phy_imr_measure_8197g(dm);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]  **********End IMR Test *******************\n");
}
void do_lok_8197g(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;	
	struct dm_iqk_info *iqk = &dm->IQK_info;	
	u32 MAC_backup[MAC_REG_NUM_8197G], BB_backup[BB_REG_NUM_8197G], RF_backup[RF_REG_NUM_8197G][SS_8197G];
	u32 backup_mac_reg[MAC_REG_NUM_8197G] = {0x520, 0x550};
	u32 backup_bb_reg[BB_REG_NUM_8197G] = {0x820, 0x824, 0x1c38, 0x1c68, 0x1d60, 0x180c, 0x410c, 0x1c3c};
	u32 backup_rf_reg[RF_REG_NUM_8197G] = {0xdf, 0x0};

	RF_DBG(dm, DBG_RF_IQK, "[IQK]  ************do Lok *****************\n");
	_iqk_macbb_8197g(dm);		
	_iqk_rf_setting_8197g(dm);
	_iqk_bb_for_dpk_setting_8197g(dm);
	_iqk_afe_setting_8197g(dm, true);
	_iqk_rfe_setting_8197g(dm, false);
	_iqk_agc_bnd_int_8197g(dm);

	_iqk_lok_setting_8197g(dm, RF_PATH_A);
	_lok_one_shot_8197g(dm, RF_PATH_A, false);

	_iqk_lok_setting_8197g(dm, RF_PATH_B);
	_lok_one_shot_8197g(dm, RF_PATH_B, false);

	_iqk_afe_setting_8197g(dm, false);
	_iqk_restore_mac_bb_8197g(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_restore_rf_8197g(dm, backup_rf_reg, RF_backup);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]  **********End Do Lok *******************\n");
}

#endif
