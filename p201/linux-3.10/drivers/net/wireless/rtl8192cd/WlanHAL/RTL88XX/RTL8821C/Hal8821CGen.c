/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8821CGen.c
	
Abstract:
	Defined RTL8821C HAL Function
	    
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
#if 0
#include "data_AGC_TAB_8821C.c"
#include "data_MAC_REG_8821C.c"
#include "data_PHY_REG_8821C.c"
#include "data_PHY_REG_MP_8821C.c"
#endif
#include "data_PHY_REG_PG_8821C.c"
#if 0
#include "data_RadioA_8821C.c"
#include "data_RadioB_8821C.c"
#endif
#include "data_rtl8821Cfw.c"

#if 0
// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "data_AGC_TAB_8821C_hp.c"
#include "data_PHY_REG_8821C_hp.c"
#include "data_RadioA_8821C_hp.c"
#include "data_RadioB_8821C_hp.c"
#endif

// Power Tracking
#include "data_TxPowerTrack_AP_8821C.c"


//3 MACDM
//default
#include "data_MACDM_def_high_8821C.c"
#include "data_MACDM_def_low_8821C.c"
#include "data_MACDM_def_normal_8821C.c"
//general
#include "data_MACDM_gen_high_8821C.c"
#include "data_MACDM_gen_low_8821C.c"
#include "data_MACDM_gen_normal_8821C.c"
//txop
#include "data_MACDM_txop_high_8821C.c"
#include "data_MACDM_txop_low_8821C.c"
#include "data_MACDM_txop_normal_8821C.c"
//criteria
#include "data_MACDM_state_criteria_8821C.c"
#endif

#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];
#if 0
VAR_MAPPING(AGC_TAB_8821C, AGC_TAB_8821C);
VAR_MAPPING(MAC_REG_8821C, MAC_REG_8821C);
VAR_MAPPING(PHY_REG_8821C, PHY_REG_8821C);
//VAR_MAPPING(PHY_REG_1T_8821C, PHY_REG_1T_8821C);
#endif
VAR_MAPPING(PHY_REG_PG_8821C, PHY_REG_PG_8821C);
#if 0
VAR_MAPPING(PHY_REG_MP_8821C, PHY_REG_MP_8821C);
VAR_MAPPING(RadioA_8821C, RadioA_8821C);
VAR_MAPPING(RadioB_8821C, RadioB_8821C);
#endif
VAR_MAPPING(rtl8821Cfw, rtl8821Cfw);

#if 0
// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
VAR_MAPPING(AGC_TAB_8821C_hp, AGC_TAB_8821C_hp);
VAR_MAPPING(PHY_REG_8821C_hp, PHY_REG_8821C_hp);
VAR_MAPPING(RadioA_8821C_hp, RadioA_8821C_hp);
VAR_MAPPING(RadioB_8821C_hp, RadioB_8821C_hp);
#endif

// Power Tracking
VAR_MAPPING(TxPowerTrack_AP_8821C, TxPowerTrack_AP_8821C);

#ifdef TXPWR_LMT_8821C
#include "../../../data_TXPWR_LMT_8821Cmp.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp,TXPWR_LMT_8821Cmp);
#include "../../../data_TXPWR_LMT_8821Cmp_Type0.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp_Type0,TXPWR_LMT_8821Cmp_Type0);
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_TXPWR_LMT_8821Cmp_Type2.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp_Type2,TXPWR_LMT_8821Cmp_Type2);
#include "../../../data_TXPWR_LMT_8821Cmp_Type3.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp_Type3,TXPWR_LMT_8821Cmp_Type3);
#include "../../../data_TXPWR_LMT_8821Cmp_Type4.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp_Type4,TXPWR_LMT_8821Cmp_Type4);
#include "../../../data_TXPWR_LMT_8821Cmp_Type5.c"
VAR_MAPPING(TXPWR_LMT_8821Cmp_Type5,TXPWR_LMT_8821Cmp_Type5);
#endif
#endif


//3 MACDM
VAR_MAPPING(MACDM_def_high_8821C, MACDM_def_high_8821C);
VAR_MAPPING(MACDM_def_low_8821C, MACDM_def_low_8821C);
VAR_MAPPING(MACDM_def_normal_8821C, MACDM_def_normal_8821C);

VAR_MAPPING(MACDM_gen_high_8821C, MACDM_gen_high_8821C);
VAR_MAPPING(MACDM_gen_low_8821C, MACDM_gen_low_8821C);
VAR_MAPPING(MACDM_gen_normal_8821C, MACDM_gen_normal_8821C);

VAR_MAPPING(MACDM_txop_high_8821C, MACDM_txop_high_8821C);
VAR_MAPPING(MACDM_txop_low_8821C, MACDM_txop_low_8821C);
VAR_MAPPING(MACDM_txop_normal_8821C, MACDM_txop_normal_8821C);

VAR_MAPPING(MACDM_state_criteria_8821C, MACDM_state_criteria_8821C);


//MP Chip
#include "data_AGC_TAB_8821Cmp.c"
#include "data_MAC_REG_8821Cmp.c"
#include "data_PHY_REG_8821Cmp.c"
#include "data_PHY_REG_MP_8821Cmp.c"
#endif
#include "data_PHY_REG_PG_8821Cmp.c"
#include "data_PHY_REG_PG_8821Cmp_Type0.c"
#if 0
#include "data_RadioA_8821Cmp.c"
#include "data_RadioB_8821Cmp.c"
#include "data_rtl8821CfwMP.c"

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "data_AGC_TAB_8821Cmp_hp.c"
#include "data_PHY_REG_8821Cmp_hp.c"
#include "data_PHY_REG_PG_8821Cmp_Type2.c"
#include "data_PHY_REG_PG_8821Cmp_Type3.c"
#include "data_PHY_REG_PG_8821Cmp_Type4.c"
#include "data_PHY_REG_PG_8821Cmp_Type5.c"
#include "data_RadioA_8821Cmp_hp.c"
#include "data_RadioB_8821Cmp_hp.c"
#endif

// Power Tracking
#include "data_TxPowerTrack_AP_8821Cmp.c"


VAR_MAPPING(AGC_TAB_8821Cmp, AGC_TAB_8821Cmp);
VAR_MAPPING(MAC_REG_8821Cmp, MAC_REG_8821Cmp);
VAR_MAPPING(PHY_REG_8821Cmp, PHY_REG_8821Cmp);
#endif
VAR_MAPPING(PHY_REG_PG_8821Cmp, PHY_REG_PG_8821Cmp);
VAR_MAPPING(PHY_REG_PG_8821Cmp_Type0, PHY_REG_PG_8821Cmp_Type0);
#if 0
VAR_MAPPING(PHY_REG_MP_8821Cmp, PHY_REG_MP_8821Cmp);
VAR_MAPPING(RadioA_8821Cmp, RadioA_8821Cmp);
VAR_MAPPING(RadioB_8821Cmp, RadioB_8821Cmp);
VAR_MAPPING(rtl8821CfwMP, rtl8821CfwMP);

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
VAR_MAPPING(AGC_TAB_8821Cmp_hp, AGC_TAB_8821Cmp_hp);
VAR_MAPPING(PHY_REG_8821Cmp_hp, PHY_REG_8821Cmp_hp);
VAR_MAPPING(PHY_REG_PG_8821Cmp_Type2, PHY_REG_PG_8821Cmp_Type2);
VAR_MAPPING(PHY_REG_PG_8821Cmp_Type3, PHY_REG_PG_8821Cmp_Type3);
VAR_MAPPING(PHY_REG_PG_8821Cmp_Type4, PHY_REG_PG_8821Cmp_Type4);
VAR_MAPPING(PHY_REG_PG_8821Cmp_Type5, PHY_REG_PG_8821Cmp_Type5);
VAR_MAPPING(RadioA_8821Cmp_hp, RadioA_8821Cmp_hp);
VAR_MAPPING(RadioB_8821Cmp_hp, RadioB_8821Cmp_hp);
#endif

// Power Tracking
VAR_MAPPING(TxPowerTrack_AP_8821Cmp, TxPowerTrack_AP_8821Cmp);
#endif

