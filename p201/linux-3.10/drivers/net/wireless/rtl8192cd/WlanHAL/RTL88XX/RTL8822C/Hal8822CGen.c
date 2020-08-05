/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8822CGen.c
	
Abstract:
	Defined RTL8822C HAL Function
	    
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
#include "data_AGC_TAB_8822C.c"
#include "data_MAC_REG_8822C.c"
#include "data_PHY_REG_8822C.c"
#include "data_PHY_REG_MP_8822C.c"
#include "data_PHY_REG_PG_8822C.c"
#include "data_RadioA_8822C.c"
#include "data_RadioB_8822C.c"
#include "data_rtl8822Cfw.c"

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "data_AGC_TAB_8822C_hp.c"
#include "data_PHY_REG_8822C_hp.c"
#include "data_RadioA_8822C_hp.c"
#include "data_RadioB_8822C_hp.c"
#endif

// Power Tracking
#include "data_TxPowerTrack_AP_8822C.c"


//3 MACDM
//default
#include "data_MACDM_def_high_8822C.c"
#include "data_MACDM_def_low_8822C.c"
#include "data_MACDM_def_normal_8822C.c"
//general
#include "data_MACDM_gen_high_8822C.c"
#include "data_MACDM_gen_low_8822C.c"
#include "data_MACDM_gen_normal_8822C.c"
//txop
#include "data_MACDM_txop_high_8822C.c"
#include "data_MACDM_txop_low_8822C.c"
#include "data_MACDM_txop_normal_8822C.c"
//criteria
#include "data_MACDM_state_criteria_8822C.c"


#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];

VAR_MAPPING(AGC_TAB_8822C, AGC_TAB_8822C);
VAR_MAPPING(MAC_REG_8822C, MAC_REG_8822C);
VAR_MAPPING(PHY_REG_8822C, PHY_REG_8822C);
//VAR_MAPPING(PHY_REG_1T_8822C, PHY_REG_1T_8822C);
VAR_MAPPING(PHY_REG_PG_8822C, PHY_REG_PG_8822C);
VAR_MAPPING(PHY_REG_MP_8822C, PHY_REG_MP_8822C);
VAR_MAPPING(RadioA_8822C, RadioA_8822C);
VAR_MAPPING(RadioB_8822C, RadioB_8822C);
VAR_MAPPING(rtl8822Cfw, rtl8822Cfw);

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
VAR_MAPPING(AGC_TAB_8822C_hp, AGC_TAB_8822C_hp);
VAR_MAPPING(PHY_REG_8822C_hp, PHY_REG_8822C_hp);
VAR_MAPPING(RadioA_8822C_hp, RadioA_8822C_hp);
VAR_MAPPING(RadioB_8822C_hp, RadioB_8822C_hp);
#endif

// Power Tracking
VAR_MAPPING(TxPowerTrack_AP_8822C, TxPowerTrack_AP_8822C);

#ifdef TXPWR_LMT_8822C
#include "../../../data_TXPWR_LMT_8822Cmp.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp,TXPWR_LMT_8822Cmp);
#include "../../../data_TXPWR_LMT_8822Cmp_Type0.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type0,TXPWR_LMT_8822Cmp_Type0);
#include "../../../data_TXPWR_LMT_8822Cmp_Type8.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type8,TXPWR_LMT_8822Cmp_Type8);
#include "../../../data_TXPWR_LMT_8822Cmp_Type9.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type9,TXPWR_LMT_8822Cmp_Type9);
#include "../../../data_TXPWR_LMT_8822Cmp_Type10.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type10,TXPWR_LMT_8822Cmp_Type10);
#include "../../../data_TXPWR_LMT_8822Cmp_Type13.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type13,TXPWR_LMT_8822Cmp_Type13);
#include "../../../data_TXPWR_LMT_8822Cmp_Type14.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type14,TXPWR_LMT_8822Cmp_Type14);


#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_TXPWR_LMT_8822Cmp_Type1.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type1,TXPWR_LMT_8822Cmp_Type1);
#include "../../../data_TXPWR_LMT_8822Cmp_Type4.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type4,TXPWR_LMT_8822Cmp_Type4);
#include "../../../data_TXPWR_LMT_8822Cmp_Type6.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type6,TXPWR_LMT_8822Cmp_Type6);
#include "../../../data_TXPWR_LMT_8822Cmp_Type7.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type7,TXPWR_LMT_8822Cmp_Type7);
#include "../../../data_TXPWR_LMT_8822Cmp_Type11.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_Type11,TXPWR_LMT_8822Cmp_Type11);
#endif
#ifdef BEAMFORMING_AUTO
#include "../../../data_TXPWR_LMT_8822Cmp_TXBF.c"
VAR_MAPPING(TXPWR_LMT_8822Cmp_TXBF,TXPWR_LMT_8822Cmp_TXBF);
#endif
#endif


//3 MACDM
VAR_MAPPING(MACDM_def_high_8822C, MACDM_def_high_8822C);
VAR_MAPPING(MACDM_def_low_8822C, MACDM_def_low_8822C);
VAR_MAPPING(MACDM_def_normal_8822C, MACDM_def_normal_8822C);

VAR_MAPPING(MACDM_gen_high_8822C, MACDM_gen_high_8822C);
VAR_MAPPING(MACDM_gen_low_8822C, MACDM_gen_low_8822C);
VAR_MAPPING(MACDM_gen_normal_8822C, MACDM_gen_normal_8822C);

VAR_MAPPING(MACDM_txop_high_8822C, MACDM_txop_high_8822C);
VAR_MAPPING(MACDM_txop_low_8822C, MACDM_txop_low_8822C);
VAR_MAPPING(MACDM_txop_normal_8822C, MACDM_txop_normal_8822C);

VAR_MAPPING(MACDM_state_criteria_8822C, MACDM_state_criteria_8822C);


//MP Chip
#include "data_AGC_TAB_8822Cmp.c"
#include "data_MAC_REG_8822Cmp.c"
#include "data_PHY_REG_8822Cmp.c"
#include "data_PHY_REG_MP_8822Cmp.c"
#include "data_PHY_REG_PG_8822Cmp.c"
#include "data_PHY_REG_PG_8822Cmp_Type0.c"
#include "data_PHY_REG_PG_8822Cmp_Type8.c"
#include "data_PHY_REG_PG_8822Cmp_Type9.c"
#include "data_PHY_REG_PG_8822Cmp_Type10.c"
#include "data_PHY_REG_PG_8822Cmp_Type13.c"
#include "data_PHY_REG_PG_8822Cmp_Type14.c"
#include "data_RadioA_8822Cmp.c"
#include "data_RadioB_8822Cmp.c"
#include "data_rtl8822CfwMP.c"

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "data_AGC_TAB_8822Cmp_hp.c"
#include "data_PHY_REG_8822Cmp_hp.c"
#include "data_PHY_REG_PG_8822Cmp_Type1.c"
#include "data_PHY_REG_PG_8822Cmp_Type4.c"
#include "data_PHY_REG_PG_8822Cmp_Type6.c"
#include "data_PHY_REG_PG_8822Cmp_Type7.c"
#include "data_PHY_REG_PG_8822Cmp_Type11.c"

#include "data_RadioA_8822Cmp_hp.c"
#include "data_RadioB_8822Cmp_hp.c"
#endif

// Power Tracking
#include "data_TxPowerTrack_AP_8822Cmp.c"


VAR_MAPPING(AGC_TAB_8822Cmp, AGC_TAB_8822Cmp);
VAR_MAPPING(MAC_REG_8822Cmp, MAC_REG_8822Cmp);
VAR_MAPPING(PHY_REG_8822Cmp, PHY_REG_8822Cmp);
VAR_MAPPING(PHY_REG_PG_8822Cmp, PHY_REG_PG_8822Cmp);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type0, PHY_REG_PG_8822Cmp_Type0);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type8, PHY_REG_PG_8822Cmp_Type8);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type9, PHY_REG_PG_8822Cmp_Type9);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type10, PHY_REG_PG_8822Cmp_Type10);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type13, PHY_REG_PG_8822Cmp_Type13);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type14, PHY_REG_PG_8822Cmp_Type14);

VAR_MAPPING(PHY_REG_MP_8822Cmp, PHY_REG_MP_8822Cmp);
VAR_MAPPING(RadioA_8822Cmp, RadioA_8822Cmp);
VAR_MAPPING(RadioB_8822Cmp, RadioB_8822Cmp);
VAR_MAPPING(rtl8822CfwMP, rtl8822CfwMP);

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
VAR_MAPPING(AGC_TAB_8822Cmp_hp, AGC_TAB_8822Cmp_hp);
VAR_MAPPING(PHY_REG_8822Cmp_hp, PHY_REG_8822Cmp_hp);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type1, PHY_REG_PG_8822Cmp_Type1);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type4, PHY_REG_PG_8822Cmp_Type4);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type6, PHY_REG_PG_8822Cmp_Type6);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type7, PHY_REG_PG_8822Cmp_Type7);
VAR_MAPPING(PHY_REG_PG_8822Cmp_Type11, PHY_REG_PG_8822Cmp_Type11);
VAR_MAPPING(RadioA_8822Cmp_hp, RadioA_8822Cmp_hp);
VAR_MAPPING(RadioB_8822Cmp_hp, RadioB_8822Cmp_hp);
#endif

// Power Tracking
VAR_MAPPING(TxPowerTrack_AP_8822Cmp, TxPowerTrack_AP_8822Cmp);


