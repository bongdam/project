/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BPhyCfg.c
	
Abstract:
	Defined HAL 8814B PHY BB setting functions
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2017-05-15 Yllin               Create.	
--*/
#if !defined(__ECOS) && !defined(CPTCFG_CFG80211_MODULE)
#include "HalPrecomp.h"
#else
#include "../../HalPrecomp.h"
#endif

// TODO: this function should be modified
void 
TXPowerTracking_ThermalMeter_Tmp8814B(
    IN  HAL_PADAPTER    Adapter
)
{
     // Do Nothing now
}

u4Byte
PHY_QueryRFReg_8814B(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      eRFPath,
	IN  u4Byte                      RegAddr,
	IN  u4Byte                      BitMask
)
{
	HAL_PADAPTER    priv     = Adapter;
	unsigned long   flags;
	u4Byte          Readback_Value;

#if CFG_HAL_DISABLE_BB_RF
	return 0;
#endif //CFG_HAL_DISABLE_BB_RF

	if(IS_HARDWARE_TYPE_8814BE(Adapter)) {
		HAL_SAVE_INT_AND_CLI(flags);
		Readback_Value = config_phydm_read_rf_reg_8814b((&(Adapter->pshare->_dmODM)), eRFPath, RegAddr, BitMask); //yllin8814B
		HAL_RESTORE_INT(flags);
		return Readback_Value;
	}
}

u4Byte
PHY_QueryRFSynReg_8814B(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      eRFPath,
	IN  u4Byte                      RegAddr,
	IN  u4Byte                      BitMask
)
{
	HAL_PADAPTER    priv     = Adapter;
	unsigned long   flags;
	u4Byte          Readback_Value;

#if CFG_HAL_DISABLE_BB_RF
	return 0;
#endif //CFG_HAL_DISABLE_BB_RF

	if(IS_HARDWARE_TYPE_8814BE(Adapter)) {
		HAL_SAVE_INT_AND_CLI(flags);
		Readback_Value = config_phydm_read_syn_reg_8814b((&(Adapter->pshare->_dmODM)), eRFPath, RegAddr, BitMask); //yllin8814B
		HAL_RESTORE_INT(flags);
		return Readback_Value;
	}

}

void
PHY_Set_SecCCATH_by_RXANT_8814B(
    IN  HAL_PADAPTER                Adapter,
    IN  u4Byte                      ulAntennaRx
)
{
	HAL_PADAPTER	priv	 = Adapter;
  //may need porting ? //yllin8814B
}

