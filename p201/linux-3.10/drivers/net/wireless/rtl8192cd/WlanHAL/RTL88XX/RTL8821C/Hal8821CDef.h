#ifndef __HAL8821C_DEF_H__
#define __HAL8821C_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8821CDef.h
	
Abstract:
	Defined HAL 8821C data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015/06/25 Eric            Create.	
--*/

// Test Chip
extern u1Byte *data_AGC_TAB_8821C_start,    *data_AGC_TAB_8821C_end;
extern u1Byte *data_MAC_REG_8821C_start,    *data_MAC_REG_8821C_end;
extern u1Byte *data_PHY_REG_8821C_start,    *data_PHY_REG_8821C_end;
//extern u1Byte *data_PHY_REG_1T_8821C_start, *data_PHY_REG_1T_8821C_end;
extern u1Byte *data_PHY_REG_MP_8821C_start, *data_PHY_REG_MP_8821C_end;
extern u1Byte *data_PHY_REG_PG_8821C_start, *data_PHY_REG_PG_8821C_end;
extern u1Byte *data_RadioA_8821C_start,     *data_RadioA_8821C_end;
extern u1Byte *data_RadioB_8821C_start,     *data_RadioB_8821C_end;


//High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_AGC_TAB_8821C_hp_start,    *data_AGC_TAB_8821C_hp_end;
extern u1Byte *data_PHY_REG_8821C_hp_start,    *data_PHY_REG_8821C_hp_end;
extern u1Byte *data_RadioA_8821C_hp_start,     *data_RadioA_8821C_hp_end;
extern u1Byte *data_RadioB_8821C_hp_start,     *data_RadioB_8821C_hp_end;
#endif

// FW
extern u1Byte *data_rtl8821Cfw_start,         *data_rtl8821Cfw_end;
extern u1Byte *data_rtl8821CfwMP_start,       *data_rtl8821CfwMP_end;

// Power Tracking
extern u1Byte *data_TxPowerTrack_AP_8821C_start,    *data_TxPowerTrack_AP_8821C_end;


//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8821C_start, *data_MACDM_def_high_8821C_end;
extern u1Byte *data_MACDM_def_low_8821C_start, *data_MACDM_def_low_8821C_end;
extern u1Byte *data_MACDM_def_normal_8821C_start, *data_MACDM_def_normal_8821C_end;

//general
extern u1Byte *data_MACDM_gen_high_8821C_start, *data_MACDM_gen_high_8821C_end;
extern u1Byte *data_MACDM_gen_low_8821C_start, *data_MACDM_gen_low_8821C_end;
extern u1Byte *data_MACDM_gen_normal_8821C_start, *data_MACDM_gen_normal_8821C_end;

//txop
extern u1Byte *data_MACDM_txop_high_8821C_start, *data_MACDM_txop_high_8821C_end;
extern u1Byte *data_MACDM_txop_low_8821C_start, *data_MACDM_txop_low_8821C_end;
extern u1Byte *data_MACDM_txop_normal_8821C_start, *data_MACDM_txop_normal_8821C_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8821C_start, *data_MACDM_state_criteria_8821C_end;


// MP chip 
extern u1Byte *data_AGC_TAB_8821Cmp_start,    *data_AGC_TAB_8821Cmp_end;
extern u1Byte *data_MAC_REG_8821Cmp_start,    *data_MAC_REG_8821Cmp_end;
extern u1Byte *data_PHY_REG_8821Cmp_start,    *data_PHY_REG_8821Cmp_end;
//extern u1Byte *data_PHY_REG_1T_8821C_start, *data_PHY_REG_1T_8821C_end;
extern u1Byte *data_PHY_REG_MP_8821Cmp_start, *data_PHY_REG_MP_8821Cmp_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_start, *data_PHY_REG_PG_8821Cmp_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_Type0_start, *data_PHY_REG_PG_8821Cmp_Type0_end;
extern u1Byte *data_RadioA_8821Cmp_start,     *data_RadioA_8821Cmp_end;
extern u1Byte *data_RadioB_8821Cmp_start,     *data_RadioB_8821Cmp_end;

//High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_AGC_TAB_8821Cmp_hp_start,    *data_AGC_TAB_8821Cmp_hp_end;
extern u1Byte *data_PHY_REG_8821Cmp_hp_start,    *data_PHY_REG_8821Cmp_hp_end;
//extern u1Byte *data_PHY_REG_PG_8821Cmp_hp_start, *data_PHY_REG_PG_8821Cmp_hp_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_Type2_start, *data_PHY_REG_PG_8821Cmp_Type2_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_Type3_start, *data_PHY_REG_PG_8821Cmp_Type3_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_Type4_start, *data_PHY_REG_PG_8821Cmp_Type4_end;
extern u1Byte *data_PHY_REG_PG_8821Cmp_Type5_start, *data_PHY_REG_PG_8821Cmp_Type5_end;
extern u1Byte *data_RadioA_8821Cmp_hp_start,     *data_RadioA_8821Cmp_hp_end;
extern u1Byte *data_RadioB_8821Cmp_hp_start,     *data_RadioB_8821Cmp_hp_end;
#endif

// FW
extern u1Byte *data_rtl8821Cfw_start,         *data_rtl8821Cfw_end;
extern u1Byte *data_rtl8821CfwMP_start,       *data_rtl8821CfwMP_end;

// Power Tracking
extern u1Byte *data_TxPowerTrack_AP_8821Cmp_start,    *data_TxPowerTrack_AP_8821Cmp_end;

#ifdef TXPWR_LMT_8821C
extern unsigned char *data_TXPWR_LMT_8821Cmp_start, *data_TXPWR_LMT_8821Cmp_end;
extern unsigned char *data_TXPWR_LMT_8821Cmp_Type0_start, *data_TXPWR_LMT_8821Cmp_Type0_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_8821Cmp_Type2_start, *data_TXPWR_LMT_8821Cmp_Type2_end;
extern unsigned char *data_TXPWR_LMT_8821Cmp_Type3_start, *data_TXPWR_LMT_8821Cmp_Type3_end;
extern unsigned char *data_TXPWR_LMT_8821Cmp_Type4_start, *data_TXPWR_LMT_8821Cmp_Type4_end;
extern unsigned char *data_TXPWR_LMT_8821Cmp_Type5_start, *data_TXPWR_LMT_8821Cmp_Type5_end;
#endif
#endif



//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8821Cmp_start, *data_MACDM_def_high_8821Cmp_end;
extern u1Byte *data_MACDM_def_low_8821Cmp_start, *data_MACDM_def_low_8821Cmp_end;
extern u1Byte *data_MACDM_def_normal_8821Cmp_start, *data_MACDM_def_normal_8821Cmp_end;

//general
extern u1Byte *data_MACDM_gen_high_8821Cmp_start, *data_MACDM_gen_high_8821Cmp_end;
extern u1Byte *data_MACDM_gen_low_8821Cmp_start, *data_MACDM_gen_low_8821Cmp_end;
extern u1Byte *data_MACDM_gen_normal_8821Cmp_start, *data_MACDM_gen_normal_8821Cmp_end;

//txop
extern u1Byte *data_MACDM_txop_high_8821Cmp_start, *data_MACDM_txop_high_8821Cmp_end;
extern u1Byte *data_MACDM_txop_low_8821Cmp_start, *data_MACDM_txop_low_8821Cmp_end;
extern u1Byte *data_MACDM_txop_normal_8821Cmp_start, *data_MACDM_txop_normal_8821Cmp_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8821Cmp_start, *data_MACDM_state_criteria_8821Cmp_end;

#endif  //__HAL8821C_DEF_H__


