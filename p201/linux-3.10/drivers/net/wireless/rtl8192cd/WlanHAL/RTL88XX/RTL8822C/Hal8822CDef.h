#ifndef __HAL8822C_DEF_H__
#define __HAL8822C_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8822CDef.h
	
Abstract:
	Defined HAL 8822C data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015/06/25 Eric            Create.	
--*/

// Test Chip
extern u1Byte *data_AGC_TAB_8822C_start,    *data_AGC_TAB_8822C_end;
extern u1Byte *data_MAC_REG_8822C_start,    *data_MAC_REG_8822C_end;
extern u1Byte *data_PHY_REG_8822C_start,    *data_PHY_REG_8822C_end;
//extern u1Byte *data_PHY_REG_1T_8822C_start, *data_PHY_REG_1T_8822C_end;
extern u1Byte *data_PHY_REG_MP_8822C_start, *data_PHY_REG_MP_8822C_end;
extern u1Byte *data_PHY_REG_PG_8822C_start, *data_PHY_REG_PG_8822C_end;
extern u1Byte *data_RadioA_8822C_start,     *data_RadioA_8822C_end;
extern u1Byte *data_RadioB_8822C_start,     *data_RadioB_8822C_end;


//High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_AGC_TAB_8822C_hp_start,    *data_AGC_TAB_8822C_hp_end;
extern u1Byte *data_PHY_REG_8822C_hp_start,    *data_PHY_REG_8822C_hp_end;
extern u1Byte *data_RadioA_8822C_hp_start,     *data_RadioA_8822C_hp_end;
extern u1Byte *data_RadioB_8822C_hp_start,     *data_RadioB_8822C_hp_end;
#endif

// FW
extern u1Byte *data_rtl8822Cfw_start,         *data_rtl8822Cfw_end;
extern u1Byte *data_rtl8822CfwMP_start,       *data_rtl8822CfwMP_end;

// Power Tracking
extern u1Byte *data_TxPowerTrack_AP_8822C_start,    *data_TxPowerTrack_AP_8822C_end;


//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8822C_start, *data_MACDM_def_high_8822C_end;
extern u1Byte *data_MACDM_def_low_8822C_start, *data_MACDM_def_low_8822C_end;
extern u1Byte *data_MACDM_def_normal_8822C_start, *data_MACDM_def_normal_8822C_end;

//general
extern u1Byte *data_MACDM_gen_high_8822C_start, *data_MACDM_gen_high_8822C_end;
extern u1Byte *data_MACDM_gen_low_8822C_start, *data_MACDM_gen_low_8822C_end;
extern u1Byte *data_MACDM_gen_normal_8822C_start, *data_MACDM_gen_normal_8822C_end;

//txop
extern u1Byte *data_MACDM_txop_high_8822C_start, *data_MACDM_txop_high_8822C_end;
extern u1Byte *data_MACDM_txop_low_8822C_start, *data_MACDM_txop_low_8822C_end;
extern u1Byte *data_MACDM_txop_normal_8822C_start, *data_MACDM_txop_normal_8822C_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8822C_start, *data_MACDM_state_criteria_8822C_end;


// MP chip 
extern u1Byte *data_AGC_TAB_8822Cmp_start,    *data_AGC_TAB_8822Cmp_end;
extern u1Byte *data_MAC_REG_8822Cmp_start,    *data_MAC_REG_8822Cmp_end;
extern u1Byte *data_PHY_REG_8822Cmp_start,    *data_PHY_REG_8822Cmp_end;
//extern u1Byte *data_PHY_REG_1T_8822C_start, *data_PHY_REG_1T_8822C_end;
extern u1Byte *data_PHY_REG_MP_8822Cmp_start, *data_PHY_REG_MP_8822Cmp_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_start, *data_PHY_REG_PG_8822Cmp_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type0_start, *data_PHY_REG_PG_8822Cmp_Type0_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type8_start, *data_PHY_REG_PG_8822Cmp_Type8_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type9_start, *data_PHY_REG_PG_8822Cmp_Type9_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type10_start, *data_PHY_REG_PG_8822Cmp_Type10_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type13_start, *data_PHY_REG_PG_8822Cmp_Type13_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type14_start, *data_PHY_REG_PG_8822Cmp_Type14_end;
extern u1Byte *data_RadioA_8822Cmp_start,     *data_RadioA_8822Cmp_end;
extern u1Byte *data_RadioB_8822Cmp_start,     *data_RadioB_8822Cmp_end;

//High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_AGC_TAB_8822Cmp_hp_start,    *data_AGC_TAB_8822Cmp_hp_end;
extern u1Byte *data_PHY_REG_8822Cmp_hp_start,    *data_PHY_REG_8822Cmp_hp_end;
//extern u1Byte *data_PHY_REG_PG_8822Cmp_hp_start, *data_PHY_REG_PG_8822Cmp_hp_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type1_start, *data_PHY_REG_PG_8822Cmp_Type1_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type4_start, *data_PHY_REG_PG_8822Cmp_Type4_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type6_start, *data_PHY_REG_PG_8822Cmp_Type6_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type7_start, *data_PHY_REG_PG_8822Cmp_Type7_end;
extern u1Byte *data_PHY_REG_PG_8822Cmp_Type11_start, *data_PHY_REG_PG_8822Cmp_Type11_end;
extern u1Byte *data_RadioA_8822Cmp_hp_start,     *data_RadioA_8822Cmp_hp_end;
extern u1Byte *data_RadioB_8822Cmp_hp_start,     *data_RadioB_8822Cmp_hp_end;
#endif

// FW
extern u1Byte *data_rtl8822Cfw_start,         *data_rtl8822Cfw_end;
extern u1Byte *data_rtl8822CfwMP_start,       *data_rtl8822CfwMP_end;

// Power Tracking
extern u1Byte *data_TxPowerTrack_AP_8822Cmp_start,    *data_TxPowerTrack_AP_8822Cmp_end;

#ifdef TXPWR_LMT_8822C
extern unsigned char *data_TXPWR_LMT_8822Cmp_start, *data_TXPWR_LMT_8822Cmp_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type0_start, *data_TXPWR_LMT_8822Cmp_Type0_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type8_start, *data_TXPWR_LMT_8822Cmp_Type8_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type9_start, *data_TXPWR_LMT_8822Cmp_Type9_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type10_start, *data_TXPWR_LMT_8822Cmp_Type10_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type13_start, *data_TXPWR_LMT_8822Cmp_Type13_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type14_start, *data_TXPWR_LMT_8822Cmp_Type14_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type1_start, *data_TXPWR_LMT_8822Cmp_Type1_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type4_start, *data_TXPWR_LMT_8822Cmp_Type4_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type6_start, *data_TXPWR_LMT_8822Cmp_Type6_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type7_start, *data_TXPWR_LMT_8822Cmp_Type7_end;
extern unsigned char *data_TXPWR_LMT_8822Cmp_Type11_start, *data_TXPWR_LMT_8822Cmp_Type11_end;
#endif
#ifdef BEAMFORMING_AUTO
extern unsigned char *data_TXPWR_LMT_8822Cmp_TXBF_start, *data_TXPWR_LMT_8822Cmp_TXBF_end;
#endif
#endif



//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8822Cmp_start, *data_MACDM_def_high_8822Cmp_end;
extern u1Byte *data_MACDM_def_low_8822Cmp_start, *data_MACDM_def_low_8822Cmp_end;
extern u1Byte *data_MACDM_def_normal_8822Cmp_start, *data_MACDM_def_normal_8822Cmp_end;

//general
extern u1Byte *data_MACDM_gen_high_8822Cmp_start, *data_MACDM_gen_high_8822Cmp_end;
extern u1Byte *data_MACDM_gen_low_8822Cmp_start, *data_MACDM_gen_low_8822Cmp_end;
extern u1Byte *data_MACDM_gen_normal_8822Cmp_start, *data_MACDM_gen_normal_8822Cmp_end;

//txop
extern u1Byte *data_MACDM_txop_high_8822Cmp_start, *data_MACDM_txop_high_8822Cmp_end;
extern u1Byte *data_MACDM_txop_low_8822Cmp_start, *data_MACDM_txop_low_8822Cmp_end;
extern u1Byte *data_MACDM_txop_normal_8822Cmp_start, *data_MACDM_txop_normal_8822Cmp_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8822Cmp_start, *data_MACDM_state_criteria_8822Cmp_end;

#endif  //__HAL8822C_DEF_H__


