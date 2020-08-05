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
 *****************************************************************************/

#include "mp_precomp.h"
/*#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)*/
#if (DM_ODM_SUPPORT_TYPE == 0x08)
/*[PHYDM-262] workaround for SD4 compile warning*/
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#if (RTL8721D_SUPPORT == 1)

/*------------------Define Local Constant----------------*/

/*  Tx Power Tracking */

void
set_iqk_matrix_8721d(struct dm_struct *dm,
		     u8 OFDM_index,
		     u8 rf_path,
		     s32 iqk_result_x,
		     s32 iqk_result_y)
{
	s32 ele_A = 0, ele_D, ele_C = 0, value32;

	ele_D = (ofdm_swing_table_new[OFDM_index] & 0xFFC00000) >> 22;

	/*new element A = element D x X*/
	if (iqk_result_x != 0) {
		if ((iqk_result_x & 0x00000200) != 0) /* consider minus */
			iqk_result_x = iqk_result_x | 0xFFFFFC00;
		ele_A = ((iqk_result_x * ele_D) >> 8) & 0x000003FF;

		/* new element C = element D x Y */
		if ((iqk_result_y & 0x00000200) != 0)
			iqk_result_y = iqk_result_y | 0xFFFFFC00;
		ele_C = ((iqk_result_y * ele_D) >> 8) & 0x000003FF;

		/* write new elements A, C, D to regC80 and regC94*/
		/* Element B is always 0 */
		value32 = (ele_D << 22) | ((ele_C & 0x3F) << 16) | ele_A;
		odm_set_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE,
			       MASKDWORD, value32);

		value32 = (ele_C & 0x000003C0) >> 6;
		odm_set_bb_reg(dm, REG_OFDM_0_XC_TX_AFE, MASKH4BITS, value32);

		value32 = ((iqk_result_x * ele_D) >> 7) & 0x01;
		odm_set_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, BIT(24), value32);
	} else {
		odm_set_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE, MASKDWORD,
			       ofdm_swing_table_new[OFDM_index]);
		odm_set_bb_reg(dm, REG_OFDM_0_XC_TX_AFE, MASKH4BITS, 0x00);
		odm_set_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, BIT(24), 0x00);
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "TxPwrTracking path %c: X = 0x%x, Y = 0x%x ele_A = 0x%x ele_C = 0x%x ele_D = 0x%x 0xeb4 = 0x%x 0xebc = 0x%x\n",
	       (rf_path == RF_PATH_A ? 'A' : 'B'), (u32)iqk_result_x,
	       (u32)iqk_result_y, (u32)ele_A, (u32)ele_C, (u32)ele_D,
	       (u32)iqk_result_x, (u32)iqk_result_y);
}

#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void
do_iqk_8721d(void *dm_void,
	     u8 delta_thermal_index,
	     u8 thermal_value,
	     u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	odm_reset_iqk_result(dm);

	dm->rf_calibrate_info.thermal_value_iqk = thermal_value;

	halrf_iqk_trigger(dm, false);
}
#else

void
do_iqk_8721d(void *dm_void,
	     u8 delta_thermal_index,
	     u8 thermal_value,
	     u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	/*boolean is_recovery = (boolean)delta_thermal_index;*/
	halrf_iqk_trigger(dm, false);
}
#endif

void
odm_tx_pwr_track_set_pwr_8721d(void *dm_void,
			       enum pwrtrack_method method,
			       u8 rf_path,
			       u8 channel_mapped_index)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	u8 channel = *dm->channel;
	u8 band_width = *dm->band_width;
	u8 pwr_tracking_limit_ofdm = 32; /* +1dB */
	u8 pwr_tracking_limit_cck = 32; /* +2dB */
	u8 tx_power_index = 0;

	s8 final_ofdm_swing_index = 0;
	s8 final_cck_swing_index = 0;
	s32 a, b;
	if (dm->cut_version > ODM_CUT_B) {
		/*IQK MATRIX NEW SITE*/
		a = 0x100;
		b = 0x0;
	} else {
		a = cali_info->iqk_matrix_reg_setting
			[channel_mapped_index].value[0][0];
		b = cali_info->iqk_matrix_reg_setting
			[channel_mapped_index].value[0][1];
	}

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "a = 0x%x, b = 0x%x\n", a, b);
	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pRF->default_ofdm_index=%d   pRF->default_cck_index=%d\n",
	       cali_info->default_ofdm_index,
	       cali_info->default_cck_index);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "pwr_tracking_limit_cck=%d      pwr_tracking_limit_ofdm=%d\n",
	       pwr_tracking_limit_cck, pwr_tracking_limit_ofdm);

	/*use for mp driver clean power tracking status*/
	/*201805 copy 8195b*/
	final_ofdm_swing_index = cali_info->default_ofdm_index +
				 cali_info->absolute_ofdm_swing_idx[rf_path];
	final_cck_swing_index = cali_info->default_cck_index +
				 cali_info->absolute_cck_swing_idx[rf_path];

	if (method == BBSWING) {
		switch (rf_path) {
		case RF_PATH_A:
			if (final_ofdm_swing_index >= pwr_tracking_limit_ofdm)
				final_ofdm_swing_index =
				pwr_tracking_limit_ofdm;
			else if (final_ofdm_swing_index < 0)
				final_ofdm_swing_index = 0;

			if (final_cck_swing_index >= CCK_TABLE_SIZE_8721D)
				final_cck_swing_index =
				CCK_TABLE_SIZE_8721D - 1;
			else if (cali_info->bb_swing_idx_cck < 0)
				final_cck_swing_index = 0;

			/* Adjust BB swing by OFDM IQ matrix */
			set_iqk_matrix_8721d(dm, final_ofdm_swing_index,
					     RF_PATH_A, a, b);
			odm_set_bb_reg(dm, R_0xab4, 0x000007FF,
				       cck_swing_table_ch1_ch14_8721d
				       [final_cck_swing_index]);
			break;

		default:
			break;
		}
	} else if (method == MIX_MODE) {
	/* CCK Follow path-A and lower CCK index means higher power. */
		switch (rf_path) {
		case RF_PATH_A:
			if (final_ofdm_swing_index > pwr_tracking_limit_ofdm) {
				/* BBSwing higher than Limit */
				cali_info->remnant_ofdm_swing_idx[rf_path] =
					(final_ofdm_swing_index -
					 pwr_tracking_limit_ofdm) * 2;
				set_iqk_matrix_8721d(dm,
						     pwr_tracking_limit_ofdm,
						     RF_PATH_A, a, b);
				cali_info->modify_tx_agc_flag_path_a = true;

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A Over BBSwing Limit, pwr_tracking_limit = %d, Remnant tx_agc value = %d\n",
				       pwr_tracking_limit_ofdm,
				       cali_info->remnant_ofdm_swing_idx
				       [rf_path]);
			} else if (final_ofdm_swing_index < 0) {
				cali_info->remnant_ofdm_swing_idx[rf_path] =
					final_ofdm_swing_index;

				set_iqk_matrix_8721d(dm, 0, RF_PATH_A, a, b);

				cali_info->modify_tx_agc_flag_path_a = true;

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A Lower then BBSwing lower bound  0, Remnant tx_agc value = %d\n",
				       cali_info->remnant_ofdm_swing_idx
				       [rf_path]);
			} else {
				set_iqk_matrix_8721d(dm, final_ofdm_swing_index,
						     RF_PATH_A, a, b);

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A Compensate with BBSwing, final_ofdm_swing_index = %d\n",
				       final_ofdm_swing_index);

				if (cali_info->modify_tx_agc_flag_path_a) {
					/* If tx_agc has changed*/
					/* reset tx_agc again */
					cali_info->remnant_ofdm_swing_idx
						[rf_path] = 0;

					cali_info->modify_tx_agc_flag_path_a =
						false;

					RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
					       "******Path_A dm->Modify_TxAGC_Flag = false\n"
					       );
				}
			}

			odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A,
							       *dm->channel,
							       OFDM);
			odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A,
							       *dm->channel,
							       HT_MCS0_MCS7);

			cali_info->modify_tx_agc_value_ofdm =
				   cali_info->remnant_ofdm_swing_idx[RF_PATH_A];
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "**==>PHY_SetTxPowerIndexByRateSection,e14 = 0x%x\n",
			       odm_get_bb_reg(dm, R_0xe14, MASKDWORD));
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "**==>PHY_SetTxPowerIndexByRateSection,c80 = 0x%x\n",
			       odm_get_bb_reg(dm, R_0xc80, MASKDWORD));

			if (final_cck_swing_index > pwr_tracking_limit_cck) {
				cali_info->remnant_cck_swing_idx =
				(final_cck_swing_index -
				 pwr_tracking_limit_cck) * 2;

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A CCK Over Limit, pwr_tracking_limit_cck = %d, cali_info->remnant_cck_swing_idx  = %d\n",
				       pwr_tracking_limit_cck,
				       cali_info->remnant_cck_swing_idx);

				/* Adjust BB swing by CCK filter coefficient */
				/* Winnita change 20170828 */
				odm_set_bb_reg(dm, R_0xab4, 0x000007FF,
					       cck_swing_table_ch1_ch14_8721d
					       [pwr_tracking_limit_cck]);

				cali_info->modify_tx_agc_flag_path_a_cck = true;

			} else if (final_cck_swing_index < 0) {
				/* Lowest CCK index = 0 */
				cali_info->remnant_cck_swing_idx =
				final_cck_swing_index;

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A CCK Under Limit, pwr_tracking_limit_cck = %d, cali_info->remnant_cck_swing_idx  = %d\n",
				       0, cali_info->remnant_cck_swing_idx);

				odm_set_bb_reg(dm, R_0xab4, 0x000007FF,
					       cck_swing_table_ch1_ch14_8721d[0]
					       );

				cali_info->modify_tx_agc_flag_path_a_cck = true;

			} else {
				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A CCK Compensate with BBSwing, final_cck_swing_index = %d\n",
				       final_cck_swing_index);

				odm_set_bb_reg(dm, R_0xab4, 0x000007FF,
					       cck_swing_table_ch1_ch14_8721d
					       [final_cck_swing_index]);

			/*if (cali_info->modify_tx_agc_flag_path_a_cck)*/
			/*{If tx_agc has changed, reset tx_agc again*/
				cali_info->remnant_cck_swing_idx = 0;

				cali_info->modify_tx_agc_flag_path_a_cck =
					false;

				RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
				       "******Path_A dm->Modify_TxAGC_Flag_CCK = false\n");
			}

			odm_set_tx_power_index_by_rate_section(dm, RF_PATH_A,
							       *dm->channel,
							       CCK);

			cali_info->modify_tx_agc_value_cck =
				cali_info->remnant_cck_swing_idx;
			RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
			       "**==>PHY_SetTxPowerIndexByRateSection,86c = 0x%x\n",
			odm_get_bb_reg(dm, R_0x86c, MASKDWORD));

			break;

		default:
			break;
		}
	}

} /* odm_TxPwrTrackSetPwr92F */

void
get_delta_swing_table_8721d(void *dm_void,
			    u8 **temperature_up_ofdm_a,
			    u8 **temperature_down_ofdm_a,
			    u8 **temperature_up_ofdm_b,
			    u8 **temperature_down_ofdm_b,
			    u8 **temperature_up_cck_a,
			    u8 **temperature_down_cck_a,
			    u8 **temperature_up_cck_b,
			    u8 **temperature_down_cck_b)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	u8 channel = *dm->channel;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "Power Tracking channel=0x%X\n",
	       channel);

	if (channel >= 1 && channel <= 14) {
		*temperature_up_ofdm_a = cali_info->delta_swing_table_idx_2ga_p;
		*temperature_down_ofdm_a = cali_info->delta_swing_table_idx_2ga_n;
	} else if (channel >= 36 && channel <= 64) {
		*temperature_up_ofdm_a = cali_info->delta_swing_table_idx_5ga_p[0];
		*temperature_down_ofdm_a = cali_info->delta_swing_table_idx_5ga_n[0];
	} else if (channel >= 100 && channel <= 144) {
		*temperature_up_ofdm_a = cali_info->delta_swing_table_idx_5ga_p[1];
		*temperature_down_ofdm_a = cali_info->delta_swing_table_idx_5ga_n[1];
	} else if (channel >= 149) {
		*temperature_up_ofdm_a = cali_info->delta_swing_table_idx_5ga_p[2];
		*temperature_down_ofdm_a = cali_info->delta_swing_table_idx_5ga_n[2];
	}
	*temperature_up_cck_a = cali_info->delta_swing_table_idx_2g_cck_a_p;
	*temperature_down_cck_a = cali_info->delta_swing_table_idx_2g_cck_a_n;
}

void
get_delta_swing_xtal_table_8721d(void *dm_void,
				 s8 **temperature_up_xtal,
				 s8 **temperature_down_xtal)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct	*cali_info = &dm->rf_calibrate_info;

	*temperature_up_xtal = cali_info->delta_swing_table_xtal_p;
	*temperature_down_xtal = cali_info->delta_swing_table_xtal_n;
}

void
odm_txxtaltrack_set_xtal_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	s8 crystal_cap;

	crystal_cap = dm->dm_cfo_track.crystal_cap_default & 0x7F;
	crystal_cap = crystal_cap + cali_info->xtal_offset;

	if (crystal_cap < 0)
		crystal_cap = 0;
	else if (crystal_cap > 127)
		crystal_cap = 127;

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK,
	       "crystal_cap(%d)= hal_data->crystal_cap(%d) + cali_info->xtal_offset(%d)\n",
	       crystal_cap, dm->dm_cfo_track.crystal_cap_default,
	       cali_info->xtal_offset);

	phydm_set_crystalcap(dm, (u8)crystal_cap);

	RF_DBG(dm, DBG_RF_TX_PWR_TRACK, "crystal_cap(0x4800_0228[30:24])= 0x%x\n",
	       HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_SYS_EFUSE_SYSCFG2));
}

void
configure_txpower_track_8721d(struct txpwrtrack_cfg *config)
{
	config->swing_table_size_cck = CCK_TABLE_SIZE_8721D;
	config->swing_table_size_ofdm = OFDM_TABLE_SIZE;
	config->threshold_iqk = IQK_THRESHOLD;
	/*config->threshold_dpk = DPK_THRESHOLD;*/
	config->average_thermal_num = AVG_THERMAL_NUM_8721D;
	config->rf_path_count = 1;
	config->thermal_reg_addr = RF_T_METER_8721D;

	config->odm_tx_pwr_track_set_pwr = odm_tx_pwr_track_set_pwr_8721d;
	config->do_iqk = do_iqk_8721d;
	config->phy_lc_calibrate = halrf_lck_trigger;
	config->get_delta_swing_table = get_delta_swing_table_8721d;
	config->get_delta_swing_xtal_table = get_delta_swing_xtal_table_8721d;
	config->odm_txxtaltrack_set_xtal = odm_txxtaltrack_set_xtal_8721d;
}

/* 1 7. IQK */
#define MAX_TOLERANCE 5
#define IQK_DELAY_TIME 1 /* ms */

u8 /* bit0 = 1 => Tx OK, bit1 = 1 => Rx OK */
phy_path_a_iqk_8721d(struct dm_struct *dm)
{
	u32 reg_eac, reg_e94, reg_e9c, rf_reg_LOI, rf_reg_LOQ, eac_bit_28;
	u32 mac_reg4;
	u8 result = 0x00, ktime = 0, i = 0;

	RF_DBG(dm, DBG_RF_IQK, "path A IQK!\n");

	/*1 Tx IQK*/
	/* path-A IQK setting */
	/*PA/PAD controlled by 0x0 */
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);  /*e28*/
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xCCF400C0);
	/*C04*/
	odm_set_bb_reg(dm, REG_OFDM_0_TRX_PATH_ENABLE, MASKDWORD, 0x03a05601);
	/*C08*/
	odm_set_bb_reg(dm, REG_OFDM_0_TR_MUX_PAR, MASKDWORD, 0x000800e4);
	/*874*/
	odm_set_bb_reg(dm, REG_FPGA0_XCD_RF_INTERFACE_SW,
		       MASKDWORD, 0x25205000);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x10000, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x40000, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, 0x40000, 0x1);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x56, 0x003ff, 0x2c);

	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x808000);

	odm_set_bb_reg(dm, REG_TX_IQK_TONE_A, MASKDWORD, 0x0800dc34);
	odm_set_bb_reg(dm, REG_RX_IQK_TONE_A, MASKDWORD, 0x2800dc34);
	odm_set_bb_reg(dm, REG_TX_IQK_PI_A, MASKDWORD, 0x8214032c);
	odm_set_bb_reg(dm, REG_RX_IQK_PI_A, MASKDWORD, 0x28160000);
	odm_set_bb_reg(dm, REG_TX_IQK, MASKDWORD, 0x01007c00);
	odm_set_bb_reg(dm, REG_RX_IQK, MASKDWORD, 0x01004800);
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xf8000800);

	mac_reg4 = odm_read_4byte(dm, 0x4);/*Shut down DAI*/
	odm_write_4byte(dm, 0x4, mac_reg4 & ~(BIT(31)));

	/* LO calibration setting*/
	odm_set_bb_reg(dm, REG_IQK_AGC_RSP, MASKDWORD, 0x00002911);

	/* One shot */
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xfa000800);
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xf8000800);

	ODM_delay_ms(IQK_DELAY_TIME_8721D);
	while ((odm_get_bb_reg(dm, R_0xe98, MASKDWORD) == 0) && ktime < 21) {
		ODM_delay_ms(2);
		ktime = ktime + 2;
	}
	odm_write_4byte(dm, 0x4, mac_reg4);/*Enable DAI*/
	RF_DBG(dm, DBG_RF_IQK, "ktime=0x%x\n", ktime);

	/* Check failed */
	reg_eac = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, MASKDWORD);
	eac_bit_28 = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, 0x10000000);
	reg_e94 = odm_get_bb_reg(dm, REG_TX_POWER_BEFORE_IQK_A, MASKDWORD);
	reg_e9c = odm_get_bb_reg(dm, REG_TX_POWER_AFTER_IQK_A, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK, "0xeac = 0x%x,eacBIT28=0x%x\n", reg_eac,
	       eac_bit_28);
	RF_DBG(dm, DBG_RF_IQK, "0xe94 = 0x%x, 0xe9c = 0x%x\n", reg_e94,
	       reg_e9c);
	/*monitor image power before & after IQK*/
	RF_DBG(dm, DBG_RF_IQK,
	       "0xe90(before IQK)= 0x%x, 0xe98(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xe90, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe98, MASKDWORD));

	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);

	rf_reg_LOI = odm_get_rf_reg(dm, RF_PATH_A, RF_0x8, 0xfc000);
	rf_reg_LOQ = odm_get_rf_reg(dm, RF_PATH_A, RF_0x8, 0x003f0);

	RF_DBG(dm, DBG_RF_IQK, "0x8[19:14]= 0x%x, 0x8[9:4] = 0x%x\n",
	       rf_reg_LOI, rf_reg_LOQ);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, BIT(16), 0x0);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x1, BIT2, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000, rf_reg_LOI);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0, rf_reg_LOQ);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, BIT(18), 0x0);

	if (!(reg_eac & BIT(28)) &&
	    (((reg_e94 & 0x03FF0000) >> 16) != 0x142) &&
	    (((reg_e9c & 0x03FF0000) >> 16) != 0x42))
		result |= 0x01;
	else
		RF_DBG(dm, DBG_RF_IQK, "pathA TX IQK is fail!\n");

	return result;
}

u8 /* bit0 = 1 => Tx OK, bit1 = 1 => Rx OK */
phy_path_a_rx_iqk_8721d(struct dm_struct *dm)
{
	u32 reg_eac, reg_e94, reg_e9c, reg_ea4, u4tmp, eac_bit_28, eac_bit_27;
	u8 result = 0x00, ktime = 0;

	RF_DBG(dm, DBG_RF_IQK, "path A Rx IQK!\n");

	/* 1 Get TXIMR setting */
	RF_DBG(dm, DBG_RF_IQK, "Get RXIQK TXIMR(step1)!\n");

	/* modify RXIQK mode table */
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);
	/* turn off power saving in RXIQK*/
	/*odm_set_rf_reg(dm, RF_PATH_A, 0x1A, 0xfffff, 0x40004);*/

	RF_DBG(dm, DBG_RF_IQK, "PATH A 0x1A = 0x%x\n",
	       odm_get_rf_reg(dm, RF_PATH_A, 0x1A, 0xfffff));
	/*	PA/PAD control by 0x56, and set = 0x0 */
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x10000, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x56, 0x3ff, 0x61);

	/* enter IQK mode */
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x808000);

	/* path-A IQK setting */
	odm_set_bb_reg(dm, REG_TX_IQK_TONE_A, MASKDWORD, 0x18008c1c);
	odm_set_bb_reg(dm, REG_RX_IQK_TONE_A, MASKDWORD, 0x38008c1c);

	odm_set_bb_reg(dm, REG_TX_IQK_PI_A, MASKDWORD, 0x8216129f);
	odm_set_bb_reg(dm, REG_RX_IQK_PI_A, MASKDWORD, 0x28160c00);

	/* IQK setting */
	odm_set_bb_reg(dm, REG_TX_IQK, MASKDWORD, 0x01007c00);
	odm_set_bb_reg(dm, REG_RX_IQK, MASKDWORD, 0x01004800);

	/* LOK off*/
	odm_set_bb_reg(dm, REG_IQK_AGC_RSP, MASKDWORD, 0x0000a911);

	/* One shot*/
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xfa000800);
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xf8000800);

	ODM_delay_ms(IQK_DELAY_TIME_8721D);
#if 0
	while ((odm_get_bb_reg(dm, R_0xe98, MASKDWORD) == 0) && ktime < 21) {
		ODM_delay_ms(5);
		ktime = ktime + 5;
	}
#endif
	/* Check failed */
	reg_eac = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, MASKDWORD);
	eac_bit_28 = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, 0x10000000);
	reg_e94 = odm_get_bb_reg(dm, REG_TX_POWER_BEFORE_IQK_A, MASKDWORD);
	reg_e9c = odm_get_bb_reg(dm, REG_TX_POWER_AFTER_IQK_A, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK, "0xeac = 0x%x,eacBIT28=0x%x\n", reg_eac,
	       eac_bit_28);
	RF_DBG(dm, DBG_RF_IQK, "0xe94 = 0x%x, 0xe9c = 0x%x\n", reg_e94,
	       reg_e9c);
	/*monitor image power before & after IQK*/
	RF_DBG(dm, DBG_RF_IQK,
	       "0xe90(before IQK)= 0x%x, 0xe98(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xe90, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe98, MASKDWORD));

	if (!(reg_eac & BIT(28)) &&
	    (((reg_e94 & 0x03FF0000) >> 16) != 0x142) &&
	    (((reg_e9c & 0x03FF0000) >> 16) != 0x42)) {
		result |= 0x01;
	} else {
		/*if Tx not OK, ignore Rx*/
		odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x10000, 0x0);
		RF_DBG(dm, DBG_RF_IQK, "pathA get TXIMR is fail\n");
		return result;
	}

	u4tmp = 0x80007C00 | (reg_e94 & 0x3FF0000) |
		((reg_e9c & 0x3FF0000) >> 16);
	odm_set_bb_reg(dm, REG_TX_IQK, MASKDWORD, u4tmp);
	RF_DBG(dm, DBG_RF_IQK, "0xe40 = 0x%x u4tmp = 0x%x\n",
	       odm_get_bb_reg(dm, REG_TX_IQK, MASKDWORD), u4tmp);

	/* RX IQK */
	RF_DBG(dm, DBG_RF_IQK, "Do RXIQK(step2)!\n");

	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x10000, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x56, 0x003ff, 0x16A);

	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xCCF000C0);

	/*enter IQK mode*/
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x808000);

	/* path-A IQK setting */
	odm_set_bb_reg(dm, REG_TX_IQK_TONE_A, MASKDWORD, 0x3800DC38);
	odm_set_bb_reg(dm, REG_RX_IQK_TONE_A, MASKDWORD, 0x1800DC38);

	odm_set_bb_reg(dm, REG_TX_IQK_PI_A, MASKDWORD, 0x82170C4A);
	odm_set_bb_reg(dm, REG_RX_IQK_PI_A, MASKDWORD, 0x28170C4A);

	odm_set_bb_reg(dm, REG_RX_IQK, MASKDWORD, 0x01004800);
	odm_set_bb_reg(dm, REG_IQK_AGC_RSP, MASKDWORD, 0x0000a911);

	/* One shot */
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xfa000800);
	odm_set_bb_reg(dm, REG_IQK_AGC_PTS, MASKDWORD, 0xf8000800);

	ODM_delay_ms(IQK_DELAY_TIME_8721D);
#if 0
	while ((!odm_get_bb_reg(dm, R_0xea8, MASKDWORD)) && ktime < 21) {
		ODM_delay_ms(5);
		ktime = ktime + 5;
	}
#endif
	/* Check failed */
	reg_eac = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, MASKDWORD);
	eac_bit_27 = odm_get_bb_reg(dm, REG_RX_POWER_AFTER_IQK_A_2, 0x08000000);
	reg_ea4 = odm_get_bb_reg(dm, REG_RX_POWER_BEFORE_IQK_A_2, MASKDWORD);
	RF_DBG(dm, DBG_RF_IQK, "0xeac = 0x%x,eacBIT27 =0x%x\n", reg_eac,
	       eac_bit_27);
	RF_DBG(dm, DBG_RF_IQK, "0xea4 = 0x%x, 0xeac = 0x%x\n", reg_ea4,
	       reg_eac);
	/* Monitor image power before & after IQK */
	RF_DBG(dm, DBG_RF_IQK,
	       "0xea0(before IQK)= 0x%x, 0xea8(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xea0, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xea8, MASKDWORD));

	/* leave IQK mode */
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xde, 0x10000, 0x0);

	if (!(reg_eac & BIT(27)) && /*if Tx is OK, check whether Rx is OK*/
	    (((reg_ea4 & 0x03FF0000) >> 16) != 0x132) &&
	    (((reg_eac & 0x03FF0000) >> 16) != 0x36))
		result |= 0x02;
	else
		RF_DBG(dm, DBG_RF_IQK, "path A Rx IQK is fail!!\n");

	return result;
}

void
_phy_path_a_fill_iqk_matrix_8721d(struct dm_struct *dm,
				  boolean is_iqk_ok,
				  s32 result[][8],
				  u8 final_candidate,
				  boolean is_tx_only)
{
	u32 oldval_0, X, TX0_A, reg;
	s32 Y, TX0_C;

	RF_DBG(dm, DBG_RF_IQK, "path A IQ Calibration %s !\n",
	       (is_iqk_ok) ? "Success" : "Failed");

	if (final_candidate == 0xFF || !(is_iqk_ok))
		return;

	if (dm->cut_version > ODM_CUT_B) {
		RF_DBG(dm, DBG_RF_IQK, "fill iqk matrix new location!\n");
		//odm_set_bb_reg(dm, R_0xc80, MASKDWORD, 0x390000e4);
		//odm_set_bb_reg(dm, R_0xc94, 0xf0000000, 0x0);

		X = result[final_candidate][0];
		if ((X & 0x00000200) != 0)
			X = X | 0xFFFFFC00;
		TX0_A = (X * 0x100) >> 8;
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK] X = 0x%x, TX0_A = 0x%x\n", X, TX0_A);
		odm_set_bb_reg(dm, R_0xe28, 0x40000000, 0x1);
		odm_set_bb_reg(dm, R_0xb40, 0x3FF, TX0_A);
		odm_set_bb_reg(dm, R_0xe28, 0x40000000, 0x0);

		Y = result[final_candidate][1];
		if ((Y & 0x00000200) != 0)
			Y = Y | 0xFFFFFC00;
		TX0_C = (Y * 0x100) >> 8;
		RF_DBG(dm, DBG_RF_IQK,
		       "[IQK] Y = 0x%x, TX0_C = 0x%x\n", Y, TX0_C);
		odm_set_bb_reg(dm,  R_0xe20, 0x000003FF, TX0_C);
	} else {
		oldval_0 = (odm_get_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE,
					   MASKDWORD) >> 22) & 0x3FF;
		X = result[final_candidate][0];
		if ((X & 0x00000200) != 0)
			X = X | 0xFFFFFC00;
		TX0_A = (X * oldval_0) >> 8;
		RF_DBG(dm, DBG_RF_IQK,
		       "X = 0x%x, TX0_A = 0x%x, oldval_0 0x%x\n", X, TX0_A,
		       oldval_0);
		odm_set_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE, 0x3FF, TX0_A);
		odm_set_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, BIT(31),
			       ((X * oldval_0 >> 7) & 0x1));

		Y = result[final_candidate][1];
		if ((Y & 0x00000200) != 0)
			Y = Y | 0xFFFFFC00;
		TX0_C = (Y * oldval_0) >> 8;
		RF_DBG(dm, DBG_RF_IQK, "Y = 0x%x, TX0_C = 0x%x\n", Y, TX0_C);
		odm_set_bb_reg(dm, REG_OFDM_0_XC_TX_AFE, 0xF0000000,
			       ((TX0_C & 0x3C0) >> 6));
		odm_set_bb_reg(dm, REG_OFDM_0_XA_TX_IQ_IMBALANCE, 0x003F0000,
			       (TX0_C & 0x3F));
		odm_set_bb_reg(dm, REG_OFDM_0_ECCA_THRESHOLD, BIT(29),
			       ((Y * oldval_0 >> 7) & 0x1));
	}

	if (is_tx_only) {
		RF_DBG(dm, DBG_RF_IQK,
		       "_phy_fill_iqk_matrix_8721d only Tx OK\n");
		return;
	}

	reg = result[final_candidate][2];

	odm_set_bb_reg(dm, REG_OFDM_0_XA_RX_IQ_IMBALANCE, 0x3FF, reg);

	reg = result[final_candidate][3] & 0x3F;
	odm_set_bb_reg(dm, REG_OFDM_0_XA_RX_IQ_IMBALANCE, 0xFC00, reg);

	reg = (result[final_candidate][3] >> 6) & 0xF;
	odm_set_bb_reg(dm, REG_OFDM_0_RX_IQ_EXT_ANTA, 0xF0000000, reg);
}

void
_phy_save_adda_registers_8721d(struct dm_struct *dm,
			       u32 *adda_reg,
			       u32 *adda_backup,
			       u32 register_num)
{
	u32 i;

	if (odm_check_power_status(dm) == false)
		return;

	/*	RF_DBG(dm,DBG_RF_IQK, ("Save ADDA parameters.\n")); */
	for (i = 0; i < register_num; i++)
		adda_backup[i] = odm_get_bb_reg(dm, adda_reg[i], MASKDWORD);
}

void
_phy_save_mac_registers_8721d(struct dm_struct *dm,
			      u32 *mac_reg,
			      u32 *mac_backup)
{
	u32 i;

	/*RF_DBG(dm,DBG_RF_IQK, ("Save MAC parameters.\n")); */
	for (i = 0; i < (IQK_MAC_REG_NUM - 1); i++)
		mac_backup[i] = odm_read_1byte(dm, mac_reg[i]);
	mac_backup[i] = odm_read_4byte(dm, mac_reg[i]);
}

void
_phy_reload_adda_registers_8721d(struct dm_struct *dm,
				 u32 *adda_reg,
				 u32 *adda_backup,
				 u32 regiester_num)
{
	u32 i;

	RF_DBG(dm, DBG_RF_IQK, "Reload ADDA power saving parameters !\n");
	for (i = 0; i < regiester_num; i++)
		odm_set_bb_reg(dm, adda_reg[i], MASKDWORD, adda_backup[i]);
}

void
_phy_reload_mac_registers_8721d(struct dm_struct *dm,
				u32 *mac_reg,
				u32 *mac_backup)
{
	u32 i;

	RF_DBG(dm, DBG_RF_IQK, "Reload MAC parameters !\n");
#if 0
	odm_set_bb_reg(dm, R_0x520, MASKBYTE2, 0x0);
#else
	for (i = 0; i < (IQK_MAC_REG_NUM - 1); i++)
		odm_write_1byte(dm, mac_reg[i], (u8)mac_backup[i]);
	odm_write_4byte(dm, mac_reg[i], mac_backup[i]);
#endif
}

void
_phy_path_adda_on_8721d(struct dm_struct *dm,
			u32 *adda_reg,
			boolean is_path_a_on,
			u8 CH_band)
{
	/*RF_DBG(dm,DBG_RF_IQK, ("[IQK] ADDA ON.\n"));*/
	/*odm_set_bb_reg(dm, R_0xd94, 0x00ff0000, 0xff);*/
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
}

void
_phy_mac_setting_calibration_8721d(struct dm_struct *dm,
				   u32 *mac_reg,
				   u32 *mac_backup)
{
#if 0
	u32 i = 0;

	RF_DBG(dm, DBG_RF_IQK, ("MAC settings for Calibration.\n"));
	odm_write_1byte(dm, mac_reg[i], 0x3F);
	for (i = 1 ; i < (IQK_MAC_REG_NUM - 1); i++)
		odm_write_1byte(dm, mac_reg[i],
				(u8)(mac_backup[i] & (~BIT(3))));

	odm_write_1byte(dm, mac_reg[i], (u8)(mac_backup[i] & (~BIT(5))));
	/* odm_set_bb_reg(dm, R_0x522, MASKBYTE0, 0x7f); */
	/* odm_set_bb_reg(dm, R_0x550, MASKBYTE0, 0x15); */
	/* odm_set_bb_reg(dm, R_0x551, MASKBYTE0, 0x00); */
#endif
	odm_set_bb_reg(dm, R_0x520, 0x00ff0000, 0xff);
	odm_set_bb_reg(dm, R_0x040, 0x20, 0x0);
	/*odm_set_bb_reg(dm, R_0x550, 0x0000ffff, 0x0015); */
}

boolean
phy_simularity_compare_8721d(struct dm_struct *dm,
			     s32 result[][8],
			     u8 c1,
			     u8 c2)
{
	u32 i, j, diff, simularity_bit_map, bound = 0;
	u8 final_candidate[2] = {0xFF, 0xFF}; /* for path A and path B */
	boolean is_result = true;
	/*#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)*/
	/*bool	is2T = IS_92C_SERIAL( hal_data->version_id);*/
	/*#else*/
	boolean is2T = true;
	/*#endif*/
	s32 tmp1 = 0, tmp2 = 0;

	if (is2T)
		bound = 8;
	else
		bound = 4;

	RF_DBG(dm, DBG_RF_IQK,
	       "===> IQK:phy simularity compare 8721d c1 %d c2 %d!!!\n",
	       c1, c2);
	simularity_bit_map = 0;
	for (i = 0; i < bound; i++) {
		if (i == 1 || i == 3 || i == 5 || i == 7) {
			if ((result[c1][i] & 0x00000200) != 0)
				tmp1 = result[c1][i] | 0xFFFFFC00;
			else
				tmp1 = result[c1][i];

			if ((result[c2][i] & 0x00000200) != 0)
				tmp2 = result[c2][i] | 0xFFFFFC00;
			else
				tmp2 = result[c2][i];
		} else {
			tmp1 = result[c1][i];
			tmp2 = result[c2][i];
		}

		diff = (tmp1 > tmp2) ? (tmp1 - tmp2) : (tmp2 - tmp1);

		if (diff > MAX_TOLERANCE) {
			RF_DBG(dm, DBG_RF_IQK,
			       "IQK:differnece overflow %d index %d compare1 0x%x compare2 0x%x!!!\n",
			       diff, i, result[c1][i], result[c2][i]);

			if ((i == 2 || i == 6) && !simularity_bit_map) {
				if (result[c1][i] + result[c1][i + 1] == 0)
					final_candidate[(i / 4)] = c2;
				else if (result[c2][i] + result[c2][i + 1] ==
					 0)
					final_candidate[(i / 4)] = c1;
				else
					simularity_bit_map =
					simularity_bit_map | (1 << i);
			} else {
				simularity_bit_map = simularity_bit_map |
						     (1 << i);
			}
		}
	}

	RF_DBG(dm, DBG_RF_IQK,
	       "IQK:phy simularity compare 8721d simularity bit_map %x !!!\n",
	       simularity_bit_map);

	if (simularity_bit_map == 0) {
		for (i = 0; i < (bound / 4); i++) {
			if (final_candidate[i] != 0xFF) {
				for (j = i * 4; j < (i + 1) * 4 - 2; j++)
					result[3][j] =
						result[final_candidate[i]][j];
				is_result = false;
			}
		}
		return is_result;
	}

	if (!(simularity_bit_map & 0x03)) { /*path A TX OK*/
		for (i = 0; i < 2; i++)
			result[3][i] = result[c1][i];
	}

	if (!(simularity_bit_map & 0x0c)) { /*path A RX OK*/
		for (i = 2; i < 4; i++)
			result[3][i] = result[c1][i];
	}

	if (!(simularity_bit_map & 0x30)) { /*path B TX OK*/
		for (i = 4; i < 6; i++)
			result[3][i] = result[c1][i];
	}

	if (!(simularity_bit_map & 0xc0)) { /*path B RX OK*/
		for (i = 6; i < 8; i++)
			result[3][i] = result[c1][i];
	}

	return false;
}

void
_phy_iq_calibrate_8721d(struct dm_struct *dm,
			s32 result[][8],
			u8 t)
{
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	u32 i;
	u8 path_aok = 0, path_bok = 0;
	u8 tmp0xc50 = (u8)odm_get_bb_reg(dm, R_0xc50, MASKBYTE0);

#if 0
	u32 ADDA_REG[2] = {
		0xd94, REG_RX_WAIT_CCA};
	u32 IQK_MAC_REG[IQK_MAC_REG_NUM] = {
		REG_TXPAUSE, REG_BCN_CTRL,
		REG_BCN_CTRL_1, REG_GPIO_MUXCFG};

	u32 IQK_BB_REG_92C[IQK_BB_REG_NUM] = {
		REG_OFDM_0_TRX_PATH_ENABLE,
		REG_OFDM_0_TR_MUX_PAR,
		REG_FPGA0_XCD_RF_INTERFACE_SW,
		REG_CONFIG_ANT_A,
		REG_CONFIG_ANT_B,
		0x92c, 0x930,
		0x938, REG_CCK_0_AFE_SETTING};
#endif

#if MP_DRIVER
	const u32 retry_count = 9;
#else
	const u32 retry_count = 2;
#endif

	/*Note: IQ calibration must be performed after loading*/
	/*PHY_REG.txt,and radio_a.txt*/
#if 0
	if (t == 0) {
		_phy_save_adda_registers_8721d(dm, ADDA_REG,
					       cali_info->ADDA_backup, 2);
		_phy_save_mac_registers_8721d(dm, IQK_MAC_REG,
					      cali_info->IQK_MAC_backup);
		_phy_save_adda_registers_8721d(dm, IQK_BB_REG_92C,
					       cali_info->IQK_BB_backup,
					       IQK_BB_REG_NUM);
	}
#endif
	RF_DBG(dm, DBG_RF_IQK, "IQ Calibration for 1T1R for %d times\n", t);

	/*_phy_path_adda_on_8721d(dm, ADDA_REG, true, CH_band);*/
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);

	/* MAC settings */
	/*_phy_mac_setting_calibration_8721d(dm, IQK_MAC_REG,*/
	/*cali_info->IQK_MAC_backup);*/

/* path A TXIQK */
#if 1
	for (i = 0; i < retry_count; i++) {
		path_aok = phy_path_a_iqk_8721d(dm);
		/*if(path_aok == 0x03){ */
		if (path_aok == 0x01) {
			RF_DBG(dm, DBG_RF_IQK, "path A Tx IQK Success!!\n");
			result[t][0] = (odm_get_bb_reg(dm,
					REG_TX_POWER_BEFORE_IQK_A, MASKDWORD) &
					0x3FF0000) >> 16;
			result[t][1] = (odm_get_bb_reg(dm,
					REG_TX_POWER_AFTER_IQK_A, MASKDWORD) &
					0x3FF0000) >> 16;
			break;
		}

		RF_DBG(dm, DBG_RF_IQK, "[IQK] path A TXIQK Fail!!\n");
		result[t][0] = 0x100;
		result[t][1] = 0x0;
#if 0
		else if (i == (retry_count - 1) && path_aok == 0x01) {
			/*Tx IQK OK*/
			RT_DISP(FINIT, INIT_IQK,
				("path A IQK Only Tx Success!!\n"));

			result[t][0] = (odm_get_bb_reg(dm,
					REG_TX_POWER_BEFORE_IQK_A,
					MASKDWORD) & 0x3FF0000) >> 16;
			result[t][1] = (odm_get_bb_reg(dm,
					REG_TX_POWER_AFTER_IQK_A, MASKDWORD)
					& 0x3FF0000) >> 16;
		}
#endif
	}
#endif

/* path A RXIQK */
#if 1
	for (i = 0; i < retry_count; i++) {
		path_aok = phy_path_a_rx_iqk_8721d(dm);
		if (path_aok == 0x03) {
			RF_DBG(dm, DBG_RF_IQK, "path A Rx IQK Success!!\n");
			/*result[t][0] = (odm_get_bb_reg(dm,*/
			/*REG_TX_POWER_BEFORE_IQK_A, MASKDWORD)&*/
			/*0x3FF0000)>>16;*/
			/*result[t][1] = (odm_get_bb_reg(dm,*/
			/*REG_TX_POWER_AFTER_IQK_A, MASKDWORD)&*/
			/*0x3FF0000)>>16;*/
			result[t][2] = (odm_get_bb_reg(dm,
					REG_RX_POWER_BEFORE_IQK_A_2,
					MASKDWORD) & 0x3FF0000) >> 16;
			result[t][3] = (odm_get_bb_reg(dm,
					REG_RX_POWER_AFTER_IQK_A_2, MASKDWORD) &
					0x3FF0000) >> 16;
			break;
		}

		RF_DBG(dm, DBG_RF_IQK, "path A Rx IQK Fail!!\n");
	}

	if (path_aok == 0x00)
		RF_DBG(dm, DBG_RF_IQK, "path A IQK failed!!\n");
#endif
	/* Back to BB mode, load original value */
	RF_DBG(dm, DBG_RF_IQK, "IQK:Back to BB mode, load original value!\n");
	odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);

	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccc400c0);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	/*c04*/
	odm_set_bb_reg(dm, REG_OFDM_0_TRX_PATH_ENABLE, MASKDWORD, 0x03a05611);
	/*c08*/
	odm_set_bb_reg(dm, REG_OFDM_0_TR_MUX_PAR, MASKDWORD, 0x000000e4);
	/*874*/
	odm_set_bb_reg(dm, REG_FPGA0_XCD_RF_INTERFACE_SW,
		       MASKDWORD, 0x25005000);

	/* Reload ADDA power saving parameters*/
	/*_phy_reload_adda_registers_8721d(dm, ADDA_REG,*/
	/*cali_info->ADDA_backup, 2);*/
	/* Reload MAC parameters*/
	/*_phy_reload_mac_registers_8721d(dm, IQK_MAC_REG,*/
	/*cali_info->IQK_MAC_backup);*/
	/*_phy_reload_adda_registers_8721d(dm, IQK_BB_REG_92C,*/
	/*cali_info->IQK_BB_backup, IQK_BB_REG_NUM);*/

	/* Restore RX initial gain*/
	odm_set_bb_reg(dm, R_0xc50, MASKBYTE0, tmp0xc50);

	RF_DBG(dm, DBG_RF_IQK, "%s <==\n", __func__);
}

void
_phy_lc_calibrate_8721d(struct dm_struct *dm, boolean is2T)
{
	u8 tmp_reg, bb_clk;
	u32 rf_amode = 0, rf_bmode = 0, lc_cal, cnt;

	RF_DBG(dm, DBG_RF_LCK, "LCK:Start!!!\n");

	/* 1.Check continuous TX and Packet TX */
	tmp_reg = odm_read_1byte(dm, 0xd03);

	/*2. Deal with contisuous TX case*/
	if ((tmp_reg & 0x70) != 0)
		odm_write_1byte(dm, 0xd03, tmp_reg & 0x8F);
	/*disable all continuous TX*/
	else
		/*2. Deal with Packet TX case*/
		odm_write_1byte(dm, REG_TXPAUSE, 0xFF);
		/* block all queues*/
	/*3. backup RF0x18*/
	lc_cal = odm_get_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK);

	/*4. Start LCK: RF reg18 bit15=1*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, 0x08000, 0x1);

	for (cnt = 0; cnt < 100; cnt++) {
		if (odm_get_rf_reg(dm, RF_PATH_A, 0xab, 0x80000) == 0x1)
			break;
		ODM_delay_ms(10);
	}

	/*5. Recover channel number*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_CHNLBW, RFREGOFFSETMASK, lc_cal);

	/*6. Restore original situation*/
	if ((tmp_reg & 0x70) != 0) {
		/*Deal with contisuous TX case*/
		odm_write_1byte(dm, 0xd03, tmp_reg);
	} else {
		/* Deal with Packet TX case*/
		odm_write_1byte(dm, REG_TXPAUSE, 0x00);
	}
	RF_DBG(dm, DBG_RF_LCK, "LCK:Stop!!!\n");
}

void
phy_iq_calibrate_8721d(void *dm_void, boolean is_recovery)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;
	s32 result[4][8]; /* last is final result */
	u32 RFreg0a, RFreg1a;
	u8 i, final_candidate, indexforchannel, channel_num, CH_band;
	boolean is_patha_ok, is_pathb_ok;
	s32 rege94, rege9c, regea4, regeac, regeb4, regebc, regec4, regecc;
	s32 reg940, reg90c;
	boolean is12simular, is13simular, is23simular;
	u32 IQK_BB_REG_92C[IQK_BB_REG_NUM] = {
		REG_OFDM_0_XA_RX_IQ_IMBALANCE, REG_OFDM_0_XB_RX_IQ_IMBALANCE,
		REG_OFDM_0_ECCA_THRESHOLD, REG_OFDM_0_AGC_RSSI_TABLE,
		REG_OFDM_0_XA_TX_IQ_IMBALANCE, REG_OFDM_0_XB_TX_IQ_IMBALANCE,
		REG_OFDM_0_XC_TX_AFE, REG_OFDM_0_XD_TX_AFE,
		REG_OFDM_0_RX_IQ_EXT_ANTA};
	u32 regpta[2];

	/*Before IC IQK develop, call void functions! Only for compile test!*/
	/*return;*/
	/*Force PTA switching to wifi temporary*/
	regpta[0] = odm_read_4byte(dm, 0x74);
	regpta[1] = odm_read_4byte(dm, 0x764);
	odm_write_4byte(dm, 0x74, 0xA);
	odm_write_4byte(dm, 0x764, 0x1a00);

	reg940 = odm_get_bb_reg(dm, R_0x940, MASKDWORD);
	reg90c = odm_get_bb_reg(dm, R_0x90c, MASKDWORD);

	RF_DBG(dm, DBG_RF_IQK, "IQK:Start!!!\n");

	RFreg0a = odm_get_rf_reg(dm, RF_PATH_A, RF_0x0, 0xfffff);

	/*Save power saving mode before RXIQK*/
	RFreg1a = odm_get_rf_reg(dm, RF_PATH_A, RF_0x1a, 0xfffff);

	/* turn off power saving in RXIQK*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x1A, 0xfffff, 0x40004);

	odm_set_bb_reg(dm, 0xb00, 0x80, 0x0); /*DPD OFF*/

	for (i = 0; i < 8; i++) {
		result[0][i] = 0;
		result[1][i] = 0;
		result[2][i] = 0;

		if (i == 0 || i == 2 || i == 4 || i == 6)
			result[3][i] = 0x100;
		else
			result[3][i] = 0;
	}

	final_candidate = 0xff;
	is_patha_ok = false;
	is_pathb_ok = false;
	is12simular = false;
	is23simular = false;
	is13simular = false;

	for (i = 0; i < 3; i++) {
		odm_set_bb_reg(dm, REG_FPGA0_IQK, 0xffffff00, 0x000000);
		_phy_iq_calibrate_8721d(dm, result, i);
		if (i == 1) {
			is12simular = phy_simularity_compare_8721d(dm, result,
								   0, 1);
			if (is12simular) {
				final_candidate = 0;
				RF_DBG(dm, DBG_RF_IQK,
				       "IQK: is12simular final_candidate is %x\n",
				       final_candidate);
				break;
			}
		}

		if (i == 2) {
			is13simular = phy_simularity_compare_8721d(dm, result,
								   0, 2);
			if (is13simular) {
				final_candidate = 0;
				RF_DBG(dm, DBG_RF_IQK,
				       "IQK: is13simular final_candidate is %x\n",
				       final_candidate);

				break;
			}
			is23simular = phy_simularity_compare_8721d(dm, result,
								   1, 2);
			if (is23simular) {
				final_candidate = 1;
				RF_DBG(dm, DBG_RF_IQK,
				       "IQK: is23simular final_candidate is %x\n",
				       final_candidate);
			} else {
				final_candidate = 3;
			}
		}
	}

	for (i = 0; i < 4; i++) {
		rege94 = result[i][0];
		rege9c = result[i][1];
		regea4 = result[i][2];
		regeac = result[i][3];
		regeb4 = result[i][4];
		regebc = result[i][5];
		regec4 = result[i][6];
		regecc = result[i][7];
	}

	if (final_candidate != 0xff) {
		rege94 = result[final_candidate][0];
		cali_info->rege94 = rege94;
		rege9c = result[final_candidate][1];
		cali_info->rege9c = rege9c;
		regea4 = result[final_candidate][2];
		regeac = result[final_candidate][3];
		regeb4 = result[final_candidate][4];
		cali_info->regeb4 = regeb4;
		regebc = result[final_candidate][5];
		cali_info->regebc = regebc;
		regec4 = result[final_candidate][6];
		regecc = result[final_candidate][7];
		RF_DBG(dm, DBG_RF_IQK, "IQK: final_candidate is %x\n",
		       final_candidate);
		is_patha_ok = true;
		is_pathb_ok = true;
	} else {
		RF_DBG(dm, DBG_RF_IQK, "IQK: FAIL use default value\n");
		/* X default value */
		cali_info->rege94 = 0x100;
		cali_info->regeb4 = 0x100;
		/* Y default value */
		cali_info->regebc = 0x0;
		cali_info->rege9c = 0x0;
	}

	if (rege94 != 0)
		_phy_path_a_fill_iqk_matrix_8721d(dm,
						  is_patha_ok,
						  result,
						  final_candidate,
						  (regea4 == 0));

	indexforchannel = odm_get_right_chnl_place_for_iqk(*dm->channel);

	/* To Fix BSOD when final_candidate is 0xff*/
	/* by sherry 20120321 */
	if (final_candidate < 4) {
		for (i = 0; i < iqk_matrix_reg_num; i++)
			cali_info->iqk_matrix_reg_setting
			[indexforchannel].value[0][i] =
				result[final_candidate][i];
		cali_info->iqk_matrix_reg_setting[indexforchannel].is_iqk_done =
			true;
	}
	/*RF_DBG(dm, DBG_RF_IQK, "\nIQK OK indexforchannel %d.\n",*/
		  /*indexforchannel);*/

	/*_phy_save_adda_registers_8721d(dm, IQK_BB_REG_92C,*/
		/*cali_info->IQK_BB_backup_recover, IQK_BB_REG_NUM);*/

	RF_DBG(dm, DBG_RF_IQK, "0xc80 = 0x%x, 0xc94 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xc80, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xc94, MASKDWORD));
	RF_DBG(dm, DBG_RF_IQK, "0xc14 = 0x%x, 0xca0 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xc14, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xca0, MASKDWORD));
	odm_set_bb_reg(dm, R_0xe28, BIT(30), 0x1);
	RF_DBG(dm, DBG_RF_IQK, "0xb40 = 0x%x, 0xe20 = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xb40, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe20, MASKDWORD));
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccc400c0);
	/*C04*/
	odm_set_bb_reg(dm, REG_OFDM_0_TRX_PATH_ENABLE, MASKDWORD, 0x03a05611);
	/*C08*/
	odm_set_bb_reg(dm, REG_OFDM_0_TR_MUX_PAR, MASKDWORD, 0x000000e4);
	/*874*/
	odm_set_bb_reg(dm, REG_FPGA0_XCD_RF_INTERFACE_SW,
		       MASKDWORD, 0x25005000);

	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);

	RF_DBG(dm, DBG_RF_IQK, "IQK finished\n");
	if (dm->cut_version > ODM_CUT_B)
		odm_set_bb_reg(dm, 0xb00, 0x80, 0x1); /*DPD ON*/

	/*restore pta*/
	odm_write_4byte(dm, 0x74, regpta[0]);
	odm_write_4byte(dm, 0x764, regpta[1]);

	/*backto power saving mode after IQK*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x1A, 0xfffff, RFreg1a);

	RF_DBG(dm, DBG_RF_IQK, "PATH A 0x1A = 0x%x\n",
	       odm_get_rf_reg(dm, RF_PATH_A, 0x1A, 0xfffff));

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, 0xfffff, RFreg0a);

	RF_DBG(dm, DBG_RF_IQK, "PATH A 0x0 = 0x%x, 0x56 = 0x%x\n",
	       odm_get_rf_reg(dm, RF_PATH_A, RF_0x0, 0xfffff),
	       odm_get_rf_reg(dm, RF_PATH_A, RF_0x56, 0xfffff));
}

void
phy_lc_calibrate_8721d(void *dm_void)
{
	boolean is_single_tone = false, is_carrier_suppression = false;
	u32 timeout = 2000, timecount = 0;
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;

	/*Before IC IQK develop, call void functions! Only for compile test!*/
	return;

#if (DM_ODM_SUPPORT_TYPE & (ODM_WIN))
	if (odm_check_power_status(dm) == false)
		return;
#endif

#if (MP_DRIVER)
	if (*dm->mp_mode &&
	    ((*rf->is_con_tx || *rf->is_single_tone ||
	     *rf->is_carrier_suppresion)))
		return;
#endif

#if DISABLE_BB_RF
	return;
#endif

#if (DM_ODM_SUPPORT_TYPE & (ODM_CE | ODM_IOT))
	if (!(rf->rf_supportability & HAL_RF_IQK))
		return;
#endif
	while (*dm->is_scan_in_process) {
		RF_DBG(dm, DBG_RF_LCK, "[LCK]scan is in process, bypass LCK\n");
		return;
#if 0
		/*driect return or timecount+?*/
		ODM_delay_ms(50);
		timecount += 50;
#endif
	}
	dm->rf_calibrate_info.is_lck_in_progress = true;
	RF_DBG(dm, DBG_RF_LCK, "LCK start!!!\n");
	_phy_lc_calibrate_8721d(dm, false);
	dm->rf_calibrate_info.is_lck_in_progress = false;
	RF_DBG(dm, DBG_RF_LCK, "LCK:Finish!!!\n");
}

void phy_set_rf_path_switch_8721d(struct dm_struct *dm, boolean is_main)
{
	u32 sysreg408 = HAL_READ32(SYSTEM_CTRL_BASE_LP, 0x0408);

	sysreg408 &= ~0x0000001F;
	sysreg408 |= 0x12;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, 0x0408, sysreg408);

	u32 sysreg410 = HAL_READ32(SYSTEM_CTRL_BASE_LP, 0x0410);
	sysreg410 &= ~0x0000001F;
	sysreg410 |= 0x12;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, 0x0410, sysreg410);

	u32 sysreg208 = HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_LP_FUNC_EN0);
	sysreg208 |= BIT(28);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_LP_FUNC_EN0, sysreg208);

	u32 sysreg344 = HAL_READ32(SYSTEM_CTRL_BASE_LP,
				   REG_AUDIO_SHARE_PAD_CTRL);

	sysreg344 |= BIT(9);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);

	u32 sysreg280 = HAL_READ32(SYSTEM_CTRL_BASE_LP, REG_LP_SYSPLL_CTRL0);
	sysreg280 |= 0x7;
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_LP_SYSPLL_CTRL0, sysreg280);

	sysreg344 |= BIT(8);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);

	sysreg344 |= BIT(0);
	HAL_WRITE32(SYSTEM_CTRL_BASE_LP, REG_AUDIO_SHARE_PAD_CTRL, sysreg344);

	odm_set_bb_reg(dm, 0x930, 0x0000FF00, 0x98);
	odm_set_bb_reg(dm, 0x870, 0x00000300, 0x3);
	odm_set_bb_reg(dm, 0x944, 0x0000000C, 0x3);

	/*odm_set_bb_reg(dm, 0x860, 0x0000FF00, 0x98);*/

	if (is_main)
		odm_set_bb_reg(dm, 0x860, 0x300, 0x1); /*mp_setrfpath 1*/
	else
		odm_set_bb_reg(dm, 0x860, 0x300, 0x2); /*mp_setrfpath 0*/
}

void phy_poll_lck_8721d(struct dm_struct *dm)
{
	u8 counter = 0x0;
	u32 temp;

	while (1) {
		temp = odm_get_rf_reg(dm, RF_PATH_A, 0xab, 0x80000);
		/*LCK_OK_BB, regAB[19]*/
		if (temp || counter > 49)
			break;
		counter++;
		ODM_delay_ms(1);
	};
	RF_DBG(dm, DBG_RF_LCK, "[LCK]counter = %d\n", counter);
}

#else /* #if (RTL8721D_SUPPORT == 1)*/

void phy_iq_calibrate_8721d(void *dm_void, boolean is_recovery) {}

void phy_lc_calibrate_8721d(void *dm_void) {}

void
odm_tx_pwr_track_set_pwr_8721d(void *dm_void,
			       enum pwrtrack_method method,
			       u8 rf_path,
			       u8 channel_mapped_index)
{
}

#endif
