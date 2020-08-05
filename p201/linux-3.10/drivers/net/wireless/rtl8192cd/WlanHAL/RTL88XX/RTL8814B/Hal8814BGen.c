/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BGen.c
	
Abstract:
	Defined RTL8814B HAL Function
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric             Create.	
--*/

#ifndef __ECOS
#include "HalPrecomp.h"
#else
#include "../../HalPrecomp.h"
#endif

// TestChip
//#include "data_AGC_TAB_8814B.c"
//#include "data_MAC_REG_8814B.c"
//#include "data_PHY_REG_8814B.c"
//#include "data_PHY_REG_MP_8814B.c"
//#include "data_PHY_REG_PG_8814B.c"
//#include "data_RadioA_8814B.c"
//#include "data_RadioB_8814B.c"
//#include "data_RadioC_8814B.c"
//#include "data_RadioD_8814B.c"
//#include "data_rtl8814Bfw.c"

//3 MACDM
//default
#include "data_MACDM_def_high_8814B.c"
#include "data_MACDM_def_low_8814B.c"
#include "data_MACDM_def_normal_8814B.c"
//general
#include "data_MACDM_gen_high_8814B.c"
#include "data_MACDM_gen_low_8814B.c"
#include "data_MACDM_gen_normal_8814B.c"
//txop
#include "data_MACDM_txop_high_8814B.c"
#include "data_MACDM_txop_low_8814B.c"
#include "data_MACDM_txop_normal_8814B.c"
//criteria
#include "data_MACDM_state_criteria_8814B.c"


#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];

//VAR_MAPPING(AGC_TAB_8814B, AGC_TAB_8814B);
//VAR_MAPPING(MAC_REG_8814B, MAC_REG_8814B);
//VAR_MAPPING(PHY_REG_8814B, PHY_REG_8814B);
//VAR_MAPPING(PHY_REG_1T_8814B, PHY_REG_1T_8814B);
//VAR_MAPPING(PHY_REG_PG_8814B, PHY_REG_PG_8814B);
//VAR_MAPPING(PHY_REG_MP_8814B, PHY_REG_MP_8814B);
//VAR_MAPPING(RadioA_8814B, RadioA_8814B);
//VAR_MAPPING(RadioB_8814B, RadioB_8814B);
//VAR_MAPPING(RadioC_8814B, RadioC_8814B);
//VAR_MAPPING(RadioD_8814B, RadioD_8814B);
//VAR_MAPPING(rtl8814Bfw, rtl8814Bfw);

#ifdef TXPWR_LMT_8814B
#include "../../../data_TXPWR_LMT_8814Bmp.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp,TXPWR_LMT_8814Bmp);
#include "../../../data_TXPWR_LMT_8814Bmp_Type0.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type0,TXPWR_LMT_8814Bmp_Type0);
#include "../../../data_TXPWR_LMT_8814Bmp_Type2.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type2,TXPWR_LMT_8814Bmp_Type2);
#include "../../../data_TXPWR_LMT_8814Bmp_Type7.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type7,TXPWR_LMT_8814Bmp_Type7);
#include "../../../data_TXPWR_LMT_8814Bmp_Type8.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type8,TXPWR_LMT_8814Bmp_Type8);
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_TXPWR_LMT_8814Bmp_Type1.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type1,TXPWR_LMT_8814Bmp_Type1);
#include "../../../data_TXPWR_LMT_8814Bmp_Type4.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type4,TXPWR_LMT_8814Bmp_Type4);
#include "../../../data_TXPWR_LMT_8814Bmp_Type5.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type5,TXPWR_LMT_8814Bmp_Type5);
#include "../../../data_TXPWR_LMT_8814Bmp_Type6.c"
VAR_MAPPING(TXPWR_LMT_8814Bmp_Type6,TXPWR_LMT_8814Bmp_Type6);
#endif
#endif


//3 MACDM
VAR_MAPPING(MACDM_def_high_8814B, MACDM_def_high_8814B);
VAR_MAPPING(MACDM_def_low_8814B, MACDM_def_low_8814B);
VAR_MAPPING(MACDM_def_normal_8814B, MACDM_def_normal_8814B);

VAR_MAPPING(MACDM_gen_high_8814B, MACDM_gen_high_8814B);
VAR_MAPPING(MACDM_gen_low_8814B, MACDM_gen_low_8814B);
VAR_MAPPING(MACDM_gen_normal_8814B, MACDM_gen_normal_8814B);

VAR_MAPPING(MACDM_txop_high_8814B, MACDM_txop_high_8814B);
VAR_MAPPING(MACDM_txop_low_8814B, MACDM_txop_low_8814B);
VAR_MAPPING(MACDM_txop_normal_8814B, MACDM_txop_normal_8814B);

VAR_MAPPING(MACDM_state_criteria_8814B, MACDM_state_criteria_8814B);


//MP Chip
#include "data_AGC_TAB_8814B.c"
#include "data_MAC_REG_8814B.c"
#include "data_PHY_REG_8814B.c"
#include "data_PHY_REG_MP_8814Bmp.c"
#include "data_PHY_REG_PG_8814Bmp.c"
#include "data_PHY_REG_PG_8814Bmp_Type0.c"
#include "data_PHY_REG_PG_8814Bmp_Type1.c"
#include "data_PHY_REG_PG_8814Bmp_Type2.c"
#include "data_PHY_REG_PG_8814Bmp_Type4.c"
#include "data_PHY_REG_PG_8814Bmp_Type5.c"
#include "data_PHY_REG_PG_8814Bmp_Type7.c"
#include "data_PHY_REG_PG_8814Bmp_Type8.c"
#include "data_RadioA_8814B.c"
#include "data_RadioB_8814B.c"
#include "data_RadioC_8814B.c"
#include "data_RadioD_8814B.c"
#include "data_RadioSyn0_8814B.c"
#include "data_RadioSyn1_8814B.c"
#include "data_rtl8814BfwMP.c"
#include "data_rtl8814BfwExtMP.c"

VAR_MAPPING(AGC_TAB_8814B, AGC_TAB_8814B);
VAR_MAPPING(MAC_REG_8814B, MAC_REG_8814B);
VAR_MAPPING(PHY_REG_8814B, PHY_REG_8814B);
VAR_MAPPING(PHY_REG_PG_8814Bmp, PHY_REG_PG_8814Bmp);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type0, PHY_REG_PG_8814Bmp_Type0);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type1, PHY_REG_PG_8814Bmp_Type1);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type2, PHY_REG_PG_8814Bmp_Type2);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type4, PHY_REG_PG_8814Bmp_Type4);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type5, PHY_REG_PG_8814Bmp_Type5);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type7, PHY_REG_PG_8814Bmp_Type7);
VAR_MAPPING(PHY_REG_PG_8814Bmp_Type8, PHY_REG_PG_8814Bmp_Type8);
VAR_MAPPING(PHY_REG_MP_8814Bmp, PHY_REG_MP_8814Bmp);
VAR_MAPPING(RadioA_8814B, RadioA_8814B);
VAR_MAPPING(RadioB_8814B, RadioB_8814B);
VAR_MAPPING(RadioC_8814B, RadioC_8814B);
VAR_MAPPING(RadioD_8814B, RadioD_8814B);
VAR_MAPPING(RadioSyn0_8814B, RadioSyn0_8814B);
VAR_MAPPING(RadioSyn1_8814B, RadioSyn1_8814B);
VAR_MAPPING(rtl8814BfwMP, rtl8814BfwMP);
VAR_MAPPING(rtl8814BfwExtMP, rtl8814BfwExtMP);

// Power Tracking
#include "../../../data_TxPowerTrack_AP_8814B.c"
#include "../../../data_TxPowerTrack_AP_8814Bmp.c"
VAR_MAPPING(TxPowerTrack_AP_8814B,TxPowerTrack_AP_8814B);
VAR_MAPPING(TxPowerTrack_AP_8814Bmp, TxPowerTrack_AP_8814Bmp);

//PE fw
#include "../../../data_wfo_rtl8192cd.c"
VAR_MAPPING(wfo_rtl8192cd, wfo_rtl8192cd);

