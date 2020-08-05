/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8192FGen.c
	
Abstract:
	Defined RTL8192F HAL Function
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2017-09-21 scko            Create.	
--*/

#if !defined(__ECOS) && !defined(CPTCFG_CFG80211_MODULE)
#include "HalPrecomp.h"
#else
#include "../../HalPrecomp.h"
#endif

#if  defined(WLAN_REG_FW_RAM_REFINE) && defined(__ECOS)
#elif (CONFIG_WLAN_CONF_TXT_EXIST==0)
#if IS_EXIST_PCI
#include "../../../data_rtl8192Ffw.c"
#include "../../../data_rtl8192FfwMP.c"
#endif
#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];

#if IS_EXIST_PCI
VAR_MAPPING(rtl8192Ffw, rtl8192Ffw);
VAR_MAPPING(rtl8192FfwMP, rtl8192FfwMP);
#endif

#else
#include "../../../data_AGC_TAB_8192F.c"
#include "../../../data_MAC_REG_8192F.c"
#include "../../../data_PHY_REG_8192F.c"
//#include "../../../data_PHY_REG_1T_8192E.c"
#include "../../../data_PHY_REG_MP_8192F.c"
#include "../../../data_PHY_REG_PG_8192F.c"
#ifdef TXPWR_LMT_92FE
#include "../../../data_PHY_REG_PG_8192F_new.c"
#endif
#include "../../../data_RadioA_8192F.c"
#include "../../../data_RadioB_8192F.c"
#if IS_EXIST_PCI
#include "../../../data_rtl8192Ffw.c"
//#include "data_RTL8192EFW_Test_T.c"
#endif

// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#ifdef PWR_BY_RATE_92F_HP			
#include "../../../data_PHY_REG_PG_8192Fmp_hp.c"
#endif
#if CFG_HAL_HIGH_POWER_EXT_LNA
#include "../../../data_AGC_TAB_8192F_hp.c"
#include "../../../data_PHY_REG_8192F_hp.c"
#include "../../../data_RadioA_8192F_hp.c"
#include "../../../data_RadioB_8192F_hp.c"
#endif
#include "../../../data_AGC_TAB_8192F_extpa.c"
#include "../../../data_PHY_REG_8192F_extpa.c"
#include "../../../data_RadioA_8192F_extpa.c"
#include "../../../data_RadioB_8192F_extpa.c"
#endif
#if CFG_HAL_HIGH_POWER_EXT_LNA
#if IS_EXIST_PCI
#include "../../../data_AGC_TAB_8192F_extlna_type1.c"
#include "../../../data_AGC_TAB_8192F_extlna_type2.c"
#include "../../../data_AGC_TAB_8192F_extlna_type3.c"
#include "../../../data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_2L.c"
#include "../../../data_AGC_TAB_8192F_extlna_dslpon_sky85201_11_4L.c"
#include "../../../data_AGC_TAB_8192F_extlna.c"
#include "../../../data_PHY_REG_8192F_extlna.c"
#include "../../../data_RadioA_8192F_extlna.c"
#include "../../../data_RadioB_8192F_extlna.c"
#endif
#if IS_EXIST_SDIO
#include "../../../data_AGC_TAB_8192FS_extlna.c"
#include "../../../data_PHY_REG_8192FS_extlna.c"
#include "../../../data_RadioA_8192FS_extlna.c"
#include "../../../data_RadioB_8192FS_extlna.c"
#endif
#endif
#if 0
// B-cut
#include "../../../data_MAC_REG_8192Eb.c"
#include "../../../data_PHY_REG_8192Eb.c"
#if IS_EXIST_PCI
#include "../../../data_RadioA_8192Eb.c"
#include "../../../data_RadioB_8192Eb.c"
#endif
//
#endif

// MP
#if IS_EXIST_PCI
#include "../../../data_AGC_TAB_8192Fmp.c"
#include "../../../data_RadioA_8192Fmp.c"
#include "../../../data_RadioB_8192Fmp.c"
#include "../../../data_RadioA_8192FmpA.c"
#include "../../../data_RadioB_8192FmpA.c"
#endif
#if IS_EXIST_SDIO
#include "../../../data_AGC_TAB_8192FS.c"
#include "../../../data_RadioA_8192FS.c"
#include "../../../data_RadioB_8192FS.c"
#endif
#include "../../../data_MAC_REG_8192Fmp.c"
#include "../../../data_PHY_REG_8192Fmp.c"
#include "../../../data_PHY_REG_MP_8192Fmp.c"
#include "../../../data_PHY_REG_PG_8192Fmp.c"
#if IS_EXIST_PCI
#include "../../../data_rtl8192FfwMP.c"
#endif
#if IS_EXIST_SDIO
#include "../../../data_rtl8192FSfwMP.c"
#endif

// Power Tracking
#if defined(CONFIG_RTL_92F_SUPPORT)
#include "../../../data_TxPowerTrack_AP_92F.c"
#else
#include "../../../data_TxPowerTrack_AP.c"
#endif

//3 MACDM
//default
#include "../../../data_MACDM_def_high_8192F.c"
#include "../../../data_MACDM_def_low_8192F.c"
#include "../../../data_MACDM_def_normal_8192F.c"
//general
#include "../../../data_MACDM_gen_high_8192F.c"
#include "../../../data_MACDM_gen_low_8192F.c"
#include "../../../data_MACDM_gen_normal_8192F.c"
//txop
#include "../../../data_MACDM_txop_high_8192F.c"
#include "../../../data_MACDM_txop_low_8192F.c"
#include "../../../data_MACDM_txop_normal_8192F.c"
//criteria
#include "../../../data_MACDM_state_criteria_8192F.c"




#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];

VAR_MAPPING(AGC_TAB_8192F, AGC_TAB_8192F);
VAR_MAPPING(MAC_REG_8192F, MAC_REG_8192F);
VAR_MAPPING(PHY_REG_8192F, PHY_REG_8192F);
//VAR_MAPPING(PHY_REG_1T_8192E, PHY_REG_1T_8192E);
VAR_MAPPING(PHY_REG_PG_8192F, PHY_REG_PG_8192F);
VAR_MAPPING(PHY_REG_MP_8192F, PHY_REG_MP_8192F);
VAR_MAPPING(RadioA_8192F, RadioA_8192F);
VAR_MAPPING(RadioB_8192F, RadioB_8192F);
#if IS_EXIST_PCI
VAR_MAPPING(rtl8192Ffw, rtl8192Ffw);
#endif

#ifdef TXPWR_LMT_92FE
VAR_MAPPING(PHY_REG_PG_8192F_new, PHY_REG_PG_8192F_new);
#endif
// High Power
#if CFG_HAL_HIGH_POWER_EXT_PA
#ifdef PWR_BY_RATE_92F_HP			
VAR_MAPPING(PHY_REG_PG_8192Fmp_hp, PHY_REG_PG_8192Fmp_hp);
#endif
#if CFG_HAL_HIGH_POWER_EXT_LNA
//VAR_MAPPING(AGC_TAB_8192E_hp, AGC_TAB_8192E_hp);
VAR_MAPPING(PHY_REG_8192F_hp, PHY_REG_8192F_hp);
VAR_MAPPING(RadioA_8192F_hp, RadioA_8192F_hp);
VAR_MAPPING(RadioB_8192F_hp, RadioB_8192F_hp);
#endif
//VAR_MAPPING(AGC_TAB_8192E_extpa, AGC_TAB_8192E_extpa);
VAR_MAPPING(PHY_REG_8192F_extpa, PHY_REG_8192F_extpa);
VAR_MAPPING(RadioA_8192F_extpa, RadioA_8192F_extpa);
VAR_MAPPING(RadioB_8192F_extpa, RadioB_8192F_extpa);
#endif

#if CFG_HAL_HIGH_POWER_EXT_LNA
#if IS_EXIST_PCI
//VAR_MAPPING(AGC_TAB_8192E_extlna, AGC_TAB_8192E_extlna);
VAR_MAPPING(PHY_REG_8192F_extlna, PHY_REG_8192F_extlna);
VAR_MAPPING(RadioA_8192F_extlna, RadioA_8192F_extlna);
VAR_MAPPING(RadioB_8192F_extlna, RadioB_8192F_extlna);
#endif
#if IS_EXIST_SDIO
VAR_MAPPING(AGC_TAB_8192FS_extlna, AGC_TAB_8192FS_extlna);
VAR_MAPPING(PHY_REG_8192FS_extlna, PHY_REG_8192FS_extlna);
VAR_MAPPING(RadioA_8192FS_extlna, RadioA_8192FS_extlna);
VAR_MAPPING(RadioB_8192FS_extlna, RadioB_8192FS_extlna);
#endif
#endif

#if IS_EXIST_PCI
#if CFG_HAL_HIGH_POWER_EXT_PA
#if CFG_HAL_HIGH_POWER_EXT_LNA
VAR_MAPPING(AGC_TAB_8192F_hp, AGC_TAB_8192F_hp);
#endif
VAR_MAPPING(AGC_TAB_8192F_extpa, AGC_TAB_8192F_extpa);
#endif

#if CFG_HAL_HIGH_POWER_EXT_LNA
VAR_MAPPING(AGC_TAB_8192F_extlna, AGC_TAB_8192F_extlna);
VAR_MAPPING(AGC_TAB_8192F_extlna_type1, AGC_TAB_8192F_extlna_type1);
VAR_MAPPING(AGC_TAB_8192F_extlna_type2, AGC_TAB_8192F_extlna_type2);
VAR_MAPPING(AGC_TAB_8192F_extlna_type3, AGC_TAB_8192F_extlna_type3);
VAR_MAPPING(AGC_TAB_8192F_extlna_dslpon_sky85201_11_2L, AGC_TAB_8192F_extlna_dslpon_sky85201_11_2L);
VAR_MAPPING(AGC_TAB_8192F_extlna_dslpon_sky85201_11_4L, AGC_TAB_8192F_extlna_dslpon_sky85201_11_4L);
#endif
#endif

#if 0
// B-cut
VAR_MAPPING(MAC_REG_8192Eb, MAC_REG_8192Eb);
VAR_MAPPING(PHY_REG_8192Eb, PHY_REG_8192Eb);
#if IS_EXIST_PCI
VAR_MAPPING(RadioA_8192Eb, RadioA_8192Eb);
VAR_MAPPING(RadioB_8192Eb, RadioB_8192Eb);
#endif
#endif

// MP
#if IS_EXIST_PCI
VAR_MAPPING(AGC_TAB_8192Fmp, AGC_TAB_8192Fmp);
VAR_MAPPING(RadioA_8192Fmp, RadioA_8192Fmp);
VAR_MAPPING(RadioB_8192Fmp, RadioB_8192Fmp);
VAR_MAPPING(RadioA_8192FmpA, RadioA_8192FmpA);
VAR_MAPPING(RadioB_8192FmpA, RadioB_8192FmpA);
#endif
#if IS_EXIST_SDIO
VAR_MAPPING(AGC_TAB_8192FS, AGC_TAB_8192FS);
VAR_MAPPING(RadioA_8192FS, RadioA_8192FS);
VAR_MAPPING(RadioB_8192FS, RadioB_8192FS);
#endif
VAR_MAPPING(MAC_REG_8192Fmp, MAC_REG_8192Fmp);
VAR_MAPPING(PHY_REG_8192Fmp, PHY_REG_8192Fmp);
VAR_MAPPING(PHY_REG_PG_8192Fmp, PHY_REG_PG_8192Fmp);
VAR_MAPPING(PHY_REG_MP_8192Fmp, PHY_REG_MP_8192Fmp);
#if IS_EXIST_PCI
VAR_MAPPING(rtl8192FfwMP, rtl8192FfwMP);
#endif
#if IS_EXIST_SDIO
VAR_MAPPING(rtl8192FSfwMP, rtl8192FSfwMP);
#endif

// Power Tracking
#if defined(CONFIG_RTL_92F_SUPPORT)
VAR_MAPPING(TxPowerTrack_AP_92F, TxPowerTrack_AP_92F);
#else
VAR_MAPPING(TxPowerTrack_AP, TxPowerTrack_AP);
#endif

#ifdef TXPWR_LMT_92FE
#include "../../../data_TXPWR_LMT_92FE_new.c"
VAR_MAPPING(TXPWR_LMT_92FE_new,TXPWR_LMT_92FE_new);
#ifdef PWR_BY_RATE_92F_HP
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_TXPWR_LMT_92FE_hp.c"
VAR_MAPPING(TXPWR_LMT_92FE_hp,TXPWR_LMT_92FE_hp);
#endif
#endif
#endif

//3 MACDM
VAR_MAPPING(MACDM_def_high_8192F, MACDM_def_high_8192F);
VAR_MAPPING(MACDM_def_low_8192F, MACDM_def_low_8192F);
VAR_MAPPING(MACDM_def_normal_8192F, MACDM_def_normal_8192F);

VAR_MAPPING(MACDM_gen_high_8192F, MACDM_gen_high_8192F);
VAR_MAPPING(MACDM_gen_low_8192F, MACDM_gen_low_8192F);
VAR_MAPPING(MACDM_gen_normal_8192F, MACDM_gen_normal_8192F);

VAR_MAPPING(MACDM_txop_high_8192F, MACDM_txop_high_8192F);
VAR_MAPPING(MACDM_txop_low_8192F, MACDM_txop_low_8192F);
VAR_MAPPING(MACDM_txop_normal_8192F, MACDM_txop_normal_8192F);

VAR_MAPPING(MACDM_state_criteria_8192F, MACDM_state_criteria_8192F);
#endif

VOID
CAMProgramEntry88XX_92F(
	IN	HAL_PADAPTER		Adapter,
	IN  u1Byte              index,
	IN  pu1Byte             macad,
	IN  pu1Byte             key128,
	IN  u2Byte              config
)
{
	u4Byte  target_command = 0, target_content = 0;
	s1Byte  entry_i = 0;

	for (entry_i = (HAL_CAM_CONTENT_USABLE_COUNT - 1); entry_i >= 2; entry_i--) {
		// polling bit, and write enable, and address
		target_command = entry_i + HAL_CAM_CONTENT_COUNT * index;
		target_command = target_command | BIT_SECCAM_POLLING | BIT_SECCAM_WE;
		target_content = (u4Byte)(*(key128 + (entry_i * 4 - 8) + 3)) << 24
						 | (u4Byte)(*(key128 + (entry_i * 4 - 8) + 2)) << 16
						 | (u4Byte)(*(key128 + (entry_i * 4 - 8) + 1)) << 8
						 | (u4Byte)(*(key128 + (entry_i * 4 - 8) + 0));

		HAL_RTL_W32(REG_CAMWRITE, target_content);
		HAL_RTL_W32(REG_CAMCMD, target_command);
	}

	/* Write entry 0 */
	target_command = HAL_CAM_CONTENT_COUNT * index;
	target_command = target_command | BIT_SECCAM_POLLING | BIT_SECCAM_WE;	
	target_content = (u4Byte)(*(macad + 0)) << 16
					 | (u4Byte)(*(macad + 1)) << 24
					 | (u4Byte)config;
	target_content = target_content | config;
	HAL_RTL_W32(REG_CAMWRITE, target_content);
	HAL_RTL_W32(REG_CAMCMD, target_command);
		
	/* then entry 1 */
	target_command = 1 + HAL_CAM_CONTENT_COUNT * index;
	target_command = target_command | BIT_SECCAM_POLLING | BIT_SECCAM_WE;	
	target_content = (u4Byte)(*(macad + 5)) << 24
					 | (u4Byte)(*(macad + 4)) << 16
					 | (u4Byte)(*(macad + 3)) << 8
					 | (u4Byte)(*(macad + 2));
	HAL_RTL_W32(REG_CAMWRITE, target_content);
	HAL_RTL_W32(REG_CAMCMD, target_command);	

	target_content = HAL_RTL_R32(REG_CR);
	if ((target_content & BIT_MAC_SEC_EN) == 0) {
		HAL_RTL_W32(REG_CR, (target_content | BIT_MAC_SEC_EN));
	}
}



