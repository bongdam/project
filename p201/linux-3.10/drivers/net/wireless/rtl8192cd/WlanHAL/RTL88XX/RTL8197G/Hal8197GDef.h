#ifndef __HAL8197G_DEF_H__
#define __HAL8197G_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8197GDef.h
	
Abstract:
	Defined HAL 8197G data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2012-03-23 Filen            Create.	
--*/


extern u1Byte *data_AGC_TAB_8197G_start,    *data_AGC_TAB_8197G_end;
extern u1Byte *data_MAC_REG_8197G_start,    *data_MAC_REG_8197G_end;
extern u1Byte *data_PHY_REG_8197G_start,    *data_PHY_REG_8197G_end;
extern u1Byte *data_RadioA_8197G_start,     *data_RadioA_8197G_end;
extern u1Byte *data_RadioB_8197G_start,     *data_RadioB_8197G_end;
extern u1Byte *data_RadioC_8197G_start,     *data_RadioC_8197G_end;
extern u1Byte *data_RadioD_8197G_start,     *data_RadioD_8197G_end;

///////////////////////////////////////////////////////////

extern u1Byte *data_MAC_REG_8197Gm_start,    *data_MAC_REG_8197Gm_end;
extern u1Byte *data_PHY_REG_8197Gm_start,    *data_PHY_REG_8197Gm_end;
extern u1Byte *data_PHY_REG_8197GMP_start,    *data_PHY_REG_8197GMP_end;

extern u1Byte *data_AGC_TAB_8197Gm_start,    *data_AGC_TAB_8197Gm_end;
extern u1Byte *data_AGC_TAB_8197GBP_start,    *data_AGC_TAB_8197GBP_end;
#ifdef CONFIG_8197G_2LAYER
extern u1Byte *data_AGC_TAB_8197GMP_2layer_start,    *data_AGC_TAB_8197GMP_2layer_end;
#endif
extern u1Byte *data_AGC_TAB_8197GMP_start,    *data_AGC_TAB_8197GMP_end;
extern u1Byte *data_AGC_TAB_8197GN_start, *data_AGC_TAB_8197GN_end;
extern u1Byte *data_AGC_TAB_8197GBP_intpa_start,    *data_AGC_TAB_8197GBP_intpa_end;
extern u1Byte *data_AGC_TAB_8197GMP_intpa_start,    *data_AGC_TAB_8197GMP_intpa_end;
extern u1Byte *data_AGC_TAB_8197GN_extpa_start, *data_AGC_TAB_8197GN_extpa_end;

extern u1Byte *data_RadioA_8197Gm_start,     *data_RadioA_8197Gm_end;
extern u1Byte *data_RadioA_8197GBP_start,     *data_RadioA_8197GBP_end;
extern u1Byte *data_RadioA_8197GMP_start,     *data_RadioA_8197GMP_end;
#ifdef CONFIG_8197G_2LAYER
extern u1Byte *data_RadioA_8197GMP_2layer_start,    *data_RadioA_8197GMP_2layer_end;
#endif
extern u1Byte *data_RadioA_8197GN_start,     *data_RadioA_8197GN_end;
extern u1Byte *data_RadioA_8197GBP_intpa_start,     *data_RadioA_8197GBP_intpa_end;
extern u1Byte *data_RadioA_8197GMP_intpa_start,     *data_RadioA_8197GMP_intpa_end;
extern u1Byte *data_RadioA_8197GN_extpa_start,     *data_RadioA_8197GN_extpa_end;

extern u1Byte *data_TxPowerTrack_AP_8197G_start, *data_TxPowerTrack_AP_8197G_end;
extern u1Byte *data_TxPowerTrack_AP_8197GMP_start, *data_TxPowerTrack_AP_8197GMP_end;
extern u1Byte *data_TxPowerTrack_AP_8197GBP_start, *data_TxPowerTrack_AP_8197GBP_end;
extern u1Byte *data_TxPowerTrack_AP_8197GN_start, *data_TxPowerTrack_AP_8197GN_end;
extern u1Byte *data_TxPowerTrack_AP_8197GMP_intpa_start, *data_TxPowerTrack_AP_8197GMP_intpa_end;
extern u1Byte *data_TxPowerTrack_AP_8197GBP_intpa_start, *data_TxPowerTrack_AP_8197GBP_intpa_end;
extern u1Byte *data_TxPowerTrack_AP_8197GN_extpa_start, *data_TxPowerTrack_AP_8197GN_extpa_end;

extern u1Byte *data_PHY_REG_PG_8197Gmp_start, *data_PHY_REG_PG_8197Gmp_end;
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type0_start, *data_PHY_REG_PG_8197Gmp_Type0_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type1_start, *data_PHY_REG_PG_8197Gmp_Type1_end;
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type2_start, *data_PHY_REG_PG_8197Gmp_Type2_end;
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type3_start, *data_PHY_REG_PG_8197Gmp_Type3_end;
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type4_start, *data_PHY_REG_PG_8197Gmp_Type4_end;
extern u1Byte *data_PHY_REG_PG_8197Gmp_Type5_start, *data_PHY_REG_PG_8197Gmp_Type5_end;
#endif

#ifdef TXPWR_LMT_8197G
extern unsigned char *data_TXPWR_LMT_8197Gmp_start, *data_TXPWR_LMT_8197Gmp_end;
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type0_start, *data_TXPWR_LMT_8197Gmp_Type0_end;
#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type1_start, *data_TXPWR_LMT_8197Gmp_Type1_end;
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type2_start, *data_TXPWR_LMT_8197Gmp_Type2_end;
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type3_start, *data_TXPWR_LMT_8197Gmp_Type3_end;
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type4_start, *data_TXPWR_LMT_8197Gmp_Type4_end;
extern unsigned char *data_TXPWR_LMT_8197Gmp_Type5_start, *data_TXPWR_LMT_8197Gmp_Type5_end;
#endif
#endif

#if 1   //Filen, file below should be updated
extern u1Byte *data_PHY_REG_MP_8197G_start, *data_PHY_REG_MP_8197G_end;
extern u1Byte *data_rtl8197Gfw_start, *data_rtl8197Gfw_end;
extern u1Byte *data_RTL8197GFW_Test_T_start, *data_RTL8197GFW_Test_T_end;
extern u1Byte *data_RTL8197GTXBUF_Test_T_start, *data_RTL8197GTXBUF_Test_T_end;
extern u1Byte *data_RTL8197GFW_A_CUT_T_start, *data_RTL8197GFW_A_CUT_T_end;
extern u1Byte *data_RTL8197GTXBUF_A_CUT_T_start, *data_RTL8197GTXBUF_A_CUT_T_end;
#endif

//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8197G_start, *data_MACDM_def_high_8197G_end;
extern u1Byte *data_MACDM_def_low_8197G_start, *data_MACDM_def_low_8197G_end;
extern u1Byte *data_MACDM_def_normal_8197G_start, *data_MACDM_def_normal_8197G_end;

//general
extern u1Byte *data_MACDM_gen_high_8197G_start, *data_MACDM_gen_high_8197G_end;
extern u1Byte *data_MACDM_gen_low_8197G_start, *data_MACDM_gen_low_8197G_end;
extern u1Byte *data_MACDM_gen_normal_8197G_start, *data_MACDM_gen_normal_8197G_end;

//txop
extern u1Byte *data_MACDM_txop_high_8197G_start, *data_MACDM_txop_high_8197G_end;
extern u1Byte *data_MACDM_txop_low_8197G_start, *data_MACDM_txop_low_8197G_end;
extern u1Byte *data_MACDM_txop_normal_8197G_start, *data_MACDM_txop_normal_8197G_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8197G_start, *data_MACDM_state_criteria_8197G_end;


enum rt_status 
StopHW8197G(
    IN  HAL_PADAPTER Adapter
);


enum rt_status 
hal_Associate_8197G(
    HAL_PADAPTER            Adapter,
    BOOLEAN			    IsDefaultAdapter
);


enum rt_status 
InitPON8197G(
    IN  HAL_PADAPTER Adapter,
    IN  u4Byte     	ClkSel        
);












#endif  //__HAL8197G_DEF_H__
