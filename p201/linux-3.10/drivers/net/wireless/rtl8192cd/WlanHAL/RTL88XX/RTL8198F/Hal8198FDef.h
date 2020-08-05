#ifndef __HAL8198F_DEF_H__
#define __HAL8198F_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8198FDef.h
	
Abstract:
	Defined HAL 8198F data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2012-03-23 Filen            Create.	
--*/


extern u1Byte *data_AGC_TAB_8198F_start,    *data_AGC_TAB_8198F_end;
extern u1Byte *data_MAC_REG_8198F_start,    *data_MAC_REG_8198F_end;
extern u1Byte *data_PHY_REG_8198F_start,    *data_PHY_REG_8198F_end;
extern u1Byte *data_RadioA_8198F_start,     *data_RadioA_8198F_end;
extern u1Byte *data_RadioB_8198F_start,     *data_RadioB_8198F_end;
extern u1Byte *data_RadioC_8198F_start,     *data_RadioC_8198F_end;
extern u1Byte *data_RadioD_8198F_start,     *data_RadioD_8198F_end;

///////////////////////////////////////////////////////////

extern u1Byte *data_MAC_REG_8198Fm_start,    *data_MAC_REG_8198Fm_end;
extern u1Byte *data_PHY_REG_8198Fm_start,    *data_PHY_REG_8198Fm_end;
extern u1Byte *data_PHY_REG_8198FMP_start,    *data_PHY_REG_8198FMP_end;

extern u1Byte *data_AGC_TAB_8198Fm_start,    *data_AGC_TAB_8198Fm_end;
extern u1Byte *data_AGC_TAB_8198FBP_start,    *data_AGC_TAB_8198FBP_end;
#ifdef CONFIG_8198F_2LAYER
extern u1Byte *data_AGC_TAB_8198FMP_2layer_start,    *data_AGC_TAB_8198FMP_2layer_end;
#endif
extern u1Byte *data_AGC_TAB_8198FMP_start,    *data_AGC_TAB_8198FMP_end;
extern u1Byte *data_AGC_TAB_8198FN_start, *data_AGC_TAB_8198FN_end;
extern u1Byte *data_AGC_TAB_8198FBP_intpa_start,    *data_AGC_TAB_8198FBP_intpa_end;
extern u1Byte *data_AGC_TAB_8198FMP_intpa_start,    *data_AGC_TAB_8198FMP_intpa_end;
extern u1Byte *data_AGC_TAB_8198FN_extpa_start, *data_AGC_TAB_8198FN_extpa_end;

extern u1Byte *data_RadioA_8198Fm_start,     *data_RadioA_8198Fm_end;
extern u1Byte *data_RadioA_8198FBP_start,     *data_RadioA_8198FBP_end;
extern u1Byte *data_RadioA_8198FMP_start,     *data_RadioA_8198FMP_end;
#ifdef CONFIG_8198F_2LAYER
extern u1Byte *data_RadioA_8198FMP_2layer_start,    *data_RadioA_8198FMP_2layer_end;
#endif
extern u1Byte *data_RadioA_8198FN_start,     *data_RadioA_8198FN_end;
extern u1Byte *data_RadioA_8198FBP_intpa_start,     *data_RadioA_8198FBP_intpa_end;
extern u1Byte *data_RadioA_8198FMP_intpa_start,     *data_RadioA_8198FMP_intpa_end;
extern u1Byte *data_RadioA_8198FN_extpa_start,     *data_RadioA_8198FN_extpa_end;

extern u1Byte *data_TxPowerTrack_AP_8198F_start, *data_TxPowerTrack_AP_8198F_end;
extern u1Byte *data_TxPowerTrack_AP_8198Fmp_start, *data_TxPowerTrack_AP_8198Fmp_end;
extern u1Byte *data_TxPowerTrack_AP_8198FBP_start, *data_TxPowerTrack_AP_8198FBP_end;
extern u1Byte *data_TxPowerTrack_AP_8198FN_start, *data_TxPowerTrack_AP_8198FN_end;
extern u1Byte *data_TxPowerTrack_AP_8198FMP_intpa_start, *data_TxPowerTrack_AP_8198FMP_intpa_end;
extern u1Byte *data_TxPowerTrack_AP_8198FBP_intpa_start, *data_TxPowerTrack_AP_8198FBP_intpa_end;
extern u1Byte *data_TxPowerTrack_AP_8198FN_extpa_start, *data_TxPowerTrack_AP_8198FN_extpa_end;

extern u1Byte *data_PHY_REG_PG_8198Fmp_start, *data_PHY_REG_PG_8198Fmp_end;
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type0_start, *data_PHY_REG_PG_8198Fmp_Type0_end;
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type2_start, *data_PHY_REG_PG_8198Fmp_Type2_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type1_start, *data_PHY_REG_PG_8198Fmp_Type1_end;
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type3_start, *data_PHY_REG_PG_8198Fmp_Type3_end;
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type4_start, *data_PHY_REG_PG_8198Fmp_Type4_end;
extern u1Byte *data_PHY_REG_PG_8198Fmp_Type5_start, *data_PHY_REG_PG_8198Fmp_Type5_end;
#endif

#ifdef TXPWR_LMT_8198F
extern unsigned char *data_TXPWR_LMT_8198Fmp_start, *data_TXPWR_LMT_8198Fmp_end;
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type0_start, *data_TXPWR_LMT_8198Fmp_Type0_end;
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type2_start, *data_TXPWR_LMT_8198Fmp_Type2_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type1_start, *data_TXPWR_LMT_8198Fmp_Type1_end;
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type3_start, *data_TXPWR_LMT_8198Fmp_Type3_end;
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type4_start, *data_TXPWR_LMT_8198Fmp_Type4_end;
extern unsigned char *data_TXPWR_LMT_8198Fmp_Type5_start, *data_TXPWR_LMT_8198Fmp_Type5_end;
#endif
#endif

#if 1   //Filen, file below should be updated
extern u1Byte *data_PHY_REG_MP_8198F_start, *data_PHY_REG_MP_8198F_end;
extern u1Byte *data_rtl8198Ffw_start, *data_rtl8198Ffw_end;
extern u1Byte *data_RTL8198FFW_Test_T_start, *data_RTL8198FFW_Test_T_end;
extern u1Byte *data_RTL8198FTXBUF_Test_T_start, *data_RTL8198FTXBUF_Test_T_end;
extern u1Byte *data_RTL8198FFW_A_CUT_T_start, *data_RTL8198FFW_A_CUT_T_end;
extern u1Byte *data_RTL8198FTXBUF_A_CUT_T_start, *data_RTL8198FTXBUF_A_CUT_T_end;
#endif

//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8198F_start, *data_MACDM_def_high_8198F_end;
extern u1Byte *data_MACDM_def_low_8198F_start, *data_MACDM_def_low_8198F_end;
extern u1Byte *data_MACDM_def_normal_8198F_start, *data_MACDM_def_normal_8198F_end;

//general
extern u1Byte *data_MACDM_gen_high_8198F_start, *data_MACDM_gen_high_8198F_end;
extern u1Byte *data_MACDM_gen_low_8198F_start, *data_MACDM_gen_low_8198F_end;
extern u1Byte *data_MACDM_gen_normal_8198F_start, *data_MACDM_gen_normal_8198F_end;

//txop
extern u1Byte *data_MACDM_txop_high_8198F_start, *data_MACDM_txop_high_8198F_end;
extern u1Byte *data_MACDM_txop_low_8198F_start, *data_MACDM_txop_low_8198F_end;
extern u1Byte *data_MACDM_txop_normal_8198F_start, *data_MACDM_txop_normal_8198F_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8198F_start, *data_MACDM_state_criteria_8198F_end;


enum rt_status 
StopHW8198F(
    IN  HAL_PADAPTER Adapter
);


enum rt_status 
hal_Associate_8198F(
    HAL_PADAPTER            Adapter,
    BOOLEAN			    IsDefaultAdapter
);


enum rt_status 
InitPON8198F(
    IN  HAL_PADAPTER Adapter,
    IN  u4Byte     	ClkSel        
);












#endif  //__HAL8198F_DEF_H__
