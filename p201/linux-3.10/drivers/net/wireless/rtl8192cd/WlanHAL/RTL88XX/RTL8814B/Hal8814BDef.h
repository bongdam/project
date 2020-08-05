#ifndef __HAL8814B_DEF_H__
#define __HAL8814B_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BDef.h
	
Abstract:
	Defined HAL 8814B data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015/06/25 Eric            Create.	
--*/

// Test Chip
//extern u1Byte *data_AGC_TAB_8814B_start,    *data_AGC_TAB_8814B_end;
//extern u1Byte *data_MAC_REG_8814B_start,    *data_MAC_REG_8814B_end;
//extern u1Byte *data_PHY_REG_8814B_start,    *data_PHY_REG_8814B_end;
//extern u1Byte *data_PHY_REG_1T_8814B_start, *data_PHY_REG_1T_8814B_end;
//extern u1Byte *data_PHY_REG_MP_8814B_start, *data_PHY_REG_MP_8814B_end;
//extern u1Byte *data_PHY_REG_PG_8814B_start, *data_PHY_REG_PG_8814B_end;
//extern u1Byte *data_RadioA_8814B_start,     *data_RadioA_8814B_end;
//extern u1Byte *data_RadioB_8814B_start,     *data_RadioB_8814B_end;
//extern u1Byte *data_RadioC_8814B_start,     *data_RadioC_8814B_end;
//extern u1Byte *data_RadioD_8814B_start,     *data_RadioD_8814B_end;
//extern u1Byte *data_RadioSyn0_8814B_start,  *data_RadioSyn0_8814B_end;
//extern u1Byte *data_RadioSyn0_8814B_start,  *data_RadioSyn1_8814B_end;


// FW
//extern u1Byte *data_rtl8814Bfw_start,         *data_rtl8814Bfw_end;
extern u1Byte *data_rtl8814BfwMP_start,       *data_rtl8814BfwMP_end;
extern u1Byte *data_rtl8814BfwExtMP_start,       *data_rtl8814BfwExtMP_end;

// Power Tracking
extern u1Byte *data_TxPowerTrack_AP_8814B_start,    *data_TxPowerTrack_AP_8814B_end;
extern u1Byte *data_TxPowerTrack_AP_8814Bmp_start,    *data_TxPowerTrack_AP_8814Bmp_end;

//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8814B_start, *data_MACDM_def_high_8814B_end;
extern u1Byte *data_MACDM_def_low_8814B_start, *data_MACDM_def_low_8814B_end;
extern u1Byte *data_MACDM_def_normal_8814B_start, *data_MACDM_def_normal_8814B_end;

//general
extern u1Byte *data_MACDM_gen_high_8814B_start, *data_MACDM_gen_high_8814B_end;
extern u1Byte *data_MACDM_gen_low_8814B_start, *data_MACDM_gen_low_8814B_end;
extern u1Byte *data_MACDM_gen_normal_8814B_start, *data_MACDM_gen_normal_8814B_end;

//txop
extern u1Byte *data_MACDM_txop_high_8814B_start, *data_MACDM_txop_high_8814B_end;
extern u1Byte *data_MACDM_txop_low_8814B_start, *data_MACDM_txop_low_8814B_end;
extern u1Byte *data_MACDM_txop_normal_8814B_start, *data_MACDM_txop_normal_8814B_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8814B_start, *data_MACDM_state_criteria_8814B_end;


// MP chip 
extern u1Byte *data_AGC_TAB_8814B_start,    *data_AGC_TAB_8814B_end;
extern u1Byte *data_MAC_REG_8814B_start,    *data_MAC_REG_8814B_end;
extern u1Byte *data_PHY_REG_8814B_start,    *data_PHY_REG_8814B_end;
//extern u1Byte *data_PHY_REG_1T_8814B_start, *data_PHY_REG_1T_8814B_end;
extern u1Byte *data_PHY_REG_MP_8814Bmp_start, *data_PHY_REG_MP_8814Bmp_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_start, *data_PHY_REG_PG_8814Bmp_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type0_start, *data_PHY_REG_PG_8814Bmp_Type0_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type2_start, *data_PHY_REG_PG_8814Bmp_Type2_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type7_start, *data_PHY_REG_PG_8814Bmp_Type7_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type8_start, *data_PHY_REG_PG_8814Bmp_Type8_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type1_start, *data_PHY_REG_PG_8814Bmp_Type1_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type4_start, *data_PHY_REG_PG_8814Bmp_Type4_end;
extern u1Byte *data_PHY_REG_PG_8814Bmp_Type5_start, *data_PHY_REG_PG_8814Bmp_Type5_end;
#endif


extern u1Byte *data_RadioA_8814B_start,     *data_RadioA_8814B_end;
extern u1Byte *data_RadioB_8814B_start,     *data_RadioB_8814B_end;
extern u1Byte *data_RadioC_8814B_start,     *data_RadioC_8814B_end;
extern u1Byte *data_RadioD_8814B_start,     *data_RadioD_8814B_end;
extern u1Byte *data_RadioSyn0_8814B_start,  *data_RadioSyn0_8814B_end;
extern u1Byte *data_RadioSyn1_8814B_start,  *data_RadioSyn1_8814B_end;

#ifdef TXPWR_LMT_8814B
extern unsigned char *data_TXPWR_LMT_8814Bmp_start, *data_TXPWR_LMT_8814Bmp_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type0_start, *data_TXPWR_LMT_8814Bmp_Type0_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type2_start, *data_TXPWR_LMT_8814Bmp_Type2_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type7_start, *data_TXPWR_LMT_8814Bmp_Type7_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type8_start, *data_TXPWR_LMT_8814Bmp_Type8_end;

#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type1_start, *data_TXPWR_LMT_8814Bmp_Type1_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type4_start, *data_TXPWR_LMT_8814Bmp_Type4_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type5_start, *data_TXPWR_LMT_8814Bmp_Type5_end;
extern unsigned char *data_TXPWR_LMT_8814Bmp_Type6_start, *data_TXPWR_LMT_8814Bmp_Type6_end;
#endif
#endif



//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8814Bmp_start, *data_MACDM_def_high_8814Bmp_end;
extern u1Byte *data_MACDM_def_low_8814Bmp_start, *data_MACDM_def_low_8814Bmp_end;
extern u1Byte *data_MACDM_def_normal_8814Bmp_start, *data_MACDM_def_normal_8814Bmp_end;

//general
extern u1Byte *data_MACDM_gen_high_8814Bmp_start, *data_MACDM_gen_high_8814Bmp_end;
extern u1Byte *data_MACDM_gen_low_8814Bmp_start, *data_MACDM_gen_low_8814Bmp_end;
extern u1Byte *data_MACDM_gen_normal_8814Bmp_start, *data_MACDM_gen_normal_8814Bmp_end;

//txop
extern u1Byte *data_MACDM_txop_high_8814Bmp_start, *data_MACDM_txop_high_8814Bmp_end;
extern u1Byte *data_MACDM_txop_low_8814Bmp_start, *data_MACDM_txop_low_8814Bmp_end;
extern u1Byte *data_MACDM_txop_normal_8814Bmp_start, *data_MACDM_txop_normal_8814Bmp_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8814Bmp_start, *data_MACDM_state_criteria_8814Bmp_end;

//PE fw
extern u1Byte *data_wfo_rtl8192cd_start, *data_wfo_rtl8192cd_end;

#endif  //__HAL8814B_DEF_H__


