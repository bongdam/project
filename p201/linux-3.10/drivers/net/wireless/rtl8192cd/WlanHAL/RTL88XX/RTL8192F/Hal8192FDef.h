#ifndef __HAL8192F_DEF_H__
#define __HAL8192F_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8192FDef.h
	
Abstract:
	Defined HAL 8192F data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2017-09-21 scko            Create.	
--*/
#if (CONFIG_WLAN_CONF_TXT_EXIST==1)
extern u1Byte *data_AGC_TAB_8192F_start,    *data_AGC_TAB_8192F_end;
extern u1Byte *data_MAC_REG_8192F_start,    *data_MAC_REG_8192F_end;
extern u1Byte *data_PHY_REG_8192F_start,    *data_PHY_REG_8192F_end;
//extern u1Byte *data_PHY_REG_1T_8192E_start, *data_PHY_REG_1T_8192E_end;
extern u1Byte *data_PHY_REG_MP_8192F_start, *data_PHY_REG_MP_8192F_end;
#ifdef TXPWR_LMT_92EE
extern u1Byte *data_PHY_REG_PG_8192F_new_start, *data_PHY_REG_PG_8192F_new_end;
#endif
extern u1Byte *data_PHY_REG_PG_8192F_start, *data_PHY_REG_PG_8192F_end;


extern u1Byte *data_RadioA_8192F_start,     *data_RadioA_8192F_end;
extern u1Byte *data_RadioB_8192F_start,     *data_RadioB_8192F_end;

//High Power

#if CFG_HAL_HIGH_POWER_EXT_PA
#ifdef PWR_BY_RATE_92F_HP			
extern u1Byte *data_PHY_REG_PG_8192Fmp_hp_start, *data_PHY_REG_PG_8192Fmp_hp_end;
#endif
#if CFG_HAL_HIGH_POWER_EXT_LNA
extern u1Byte *data_AGC_TAB_8192F_hp_start,    *data_AGC_TAB_8192F_hp_end;
extern u1Byte *data_PHY_REG_8192F_hp_start,    *data_PHY_REG_8192F_hp_end;
extern u1Byte *data_RadioA_8192F_hp_start,     *data_RadioA_8192F_hp_end;
extern u1Byte *data_RadioB_8192F_hp_start,     *data_RadioB_8192F_hp_end;
#endif
extern u1Byte *data_AGC_TAB_8192F_extpa_start,    *data_AGC_TAB_8192F_extpa_end;
extern u1Byte *data_PHY_REG_8192F_extpa_start,    *data_PHY_REG_8192F_extpa_end;
extern u1Byte *data_RadioA_8192F_extpa_start,     *data_RadioA_8192F_extpa_end;
extern u1Byte *data_RadioB_8192F_extpa_start,     *data_RadioB_8192F_extpa_end;
#endif

#if CFG_HAL_HIGH_POWER_EXT_LNA
#if IS_EXIST_PCI
extern u1Byte *data_AGC_TAB_8192F_extlna_start,    *data_AGC_TAB_8192F_extlna_end;
extern u1Byte *data_AGC_TAB_8192F_extlna_type1_start,   *data_AGC_TAB_8192F_extlna_type1_end;
extern u1Byte *data_AGC_TAB_8192F_extlna_type2_start,   *data_AGC_TAB_8192F_extlna_type2_end;
extern u1Byte *data_AGC_TAB_8192F_extlna_type3_start,   *data_AGC_TAB_8192F_extlna_type3_end;	
extern u1Byte *data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_2L_start,   *data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_2L_end;
extern u1Byte *data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_4L_start,   *data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_4L_end;
extern u1Byte *data_PHY_REG_8192F_extlna_start,    *data_PHY_REG_8192F_extlna_end;
extern u1Byte *data_RadioA_8192F_extlna_start,     *data_RadioA_8192F_extlna_end;
extern u1Byte *data_RadioB_8192F_extlna_start,     *data_RadioB_8192F_extlna_end;
#endif
#if IS_EXIST_SDIO
extern u1Byte *data_AGC_TAB_8192FS_extlna_start,    *data_AGC_TAB_8192FS_extlna_end;
extern u1Byte *data_PHY_REG_8192FS_extlna_start,    *data_PHY_REG_8192FS_extlna_end;
extern u1Byte *data_RadioA_8192FS_extlna_start,     *data_RadioA_8192FS_extlna_end;
extern u1Byte *data_RadioB_8192FS_extlna_start,     *data_RadioB_8192FS_extlna_end;
#endif
#endif

#if 0
// B-cut support
extern u1Byte *data_MAC_REG_8192Eb_start,    *data_MAC_REG_8192Eb_end;
extern u1Byte *data_PHY_REG_8192Eb_start,    *data_PHY_REG_8192Eb_end;
#if IS_EXIST_PCI
extern u1Byte *data_RadioA_8192Eb_start,     *data_RadioA_8192Eb_end;
extern u1Byte *data_RadioB_8192Eb_start,     *data_RadioB_8192Eb_end;
#endif
#endif

// MP chip 
#if IS_EXIST_PCI
extern u1Byte *data_AGC_TAB_8192Fmp_start,    *data_AGC_TAB_8192Fmp_end;
extern u1Byte *data_RadioA_8192Fmp_start,     *data_RadioA_8192Fmp_end;
extern u1Byte *data_RadioB_8192Fmp_start,     *data_RadioB_8192Fmp_end;
extern u1Byte *data_RadioA_8192FmpA_start,     *data_RadioA_8192FmpA_end;
extern u1Byte *data_RadioB_8192FmpA_start,     *data_RadioB_8192FmpA_end;
#endif
#if IS_EXIST_SDIO
extern u1Byte *data_AGC_TAB_8192FS_start,    *data_AGC_TAB_8192FS_end;
extern u1Byte *data_RadioA_8192FS_start,     *data_RadioA_8192FS_end;
extern u1Byte *data_RadioB_8192FS_start,     *data_RadioB_8192FS_end;
#endif
extern u1Byte *data_PHY_REG_MP_8192Fmp_start, *data_PHY_REG_MP_8192Fmp_end;
extern u1Byte *data_PHY_REG_PG_8192Fmp_start, *data_PHY_REG_PG_8192Fmp_end;
extern u1Byte *data_MAC_REG_8192Fmp_start,    *data_MAC_REG_8192Fmp_end;
extern u1Byte *data_PHY_REG_8192Fmp_start,    *data_PHY_REG_8192Fmp_end;

#endif

// FW
#if IS_EXIST_PCI
extern u1Byte *data_rtl8192Ffw_start,         *data_rtl8192Ffw_end;
extern u1Byte *data_rtl8192FfwMP_start,       *data_rtl8192FfwMP_end;
#endif
#if IS_EXIST_SDIO
extern u1Byte *data_rtl8192FSfwMP_start,       *data_rtl8192FSfwMP_end;
#endif

#if (CONFIG_WLAN_CONF_TXT_EXIST==1)
// Power Tracking
#if defined(CONFIG_RTL_92F_SUPPORT)
extern u1Byte *data_TxPowerTrack_AP_92F_start,    *data_TxPowerTrack_AP_92F_end;
#else
extern u1Byte *data_TxPowerTrack_AP_start,    *data_TxPowerTrack_AP_end;
#endif

#ifdef TXPWR_LMT_92EE
extern unsigned char *data_TXPWR_LMT_92FE_new_start, *data_TXPWR_LMT_92FE_new_end;
#ifdef PWR_BY_RATE_92E_HP
#if CFG_HAL_HIGH_POWER_EXT_PA
extern unsigned char *data_TXPWR_LMT_92FE_hp_start, *data_TXPWR_LMT_92FE_hp_end;
#endif
#endif
#endif

//3 MACDM
//default
extern u1Byte *data_MACDM_def_high_8192F_start, *data_MACDM_def_high_8192F_end;
extern u1Byte *data_MACDM_def_low_8192F_start, *data_MACDM_def_low_8192F_end;
extern u1Byte *data_MACDM_def_normal_8192F_start, *data_MACDM_def_normal_8192F_end;

//general
extern u1Byte *data_MACDM_gen_high_8192F_start, *data_MACDM_gen_high_8192F_end;
extern u1Byte *data_MACDM_gen_low_8192F_start, *data_MACDM_gen_low_8192F_end;
extern u1Byte *data_MACDM_gen_normal_8192F_start, *data_MACDM_gen_normal_8192F_end;

//txop
extern u1Byte *data_MACDM_txop_high_8192F_start, *data_MACDM_txop_high_8192F_end;
extern u1Byte *data_MACDM_txop_low_8192F_start, *data_MACDM_txop_low_8192F_end;
extern u1Byte *data_MACDM_txop_normal_8192F_start, *data_MACDM_txop_normal_8192F_end;

//criteria
extern u1Byte *data_MACDM_state_criteria_8192F_start, *data_MACDM_state_criteria_8192F_end;
#endif

VOID
CAMProgramEntry88XX_92F(
	IN	HAL_PADAPTER		Adapter,
	IN  u1Byte              index,
	IN  pu1Byte             macad,
	IN  pu1Byte             key128,
	IN  u2Byte              config
);

#endif  //__HAL8192E_DEF_H__


