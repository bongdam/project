#ifndef __HAL8814BPHYCFG_H__
#define __HAL8814BPHYCFG_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BPhyCfg.h
	
Abstract:
	Defined HAL 8814B PHY BB setting functions
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric               Create.	
--*/

void 
TXPowerTracking_ThermalMeter_Tmp8814B(
    IN  HAL_PADAPTER    Adapter
);

u4Byte
PHY_QueryRFReg_8814B(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      eRFPath,
	IN  u4Byte                      RegAddr,
	IN  u4Byte                      BitMask
);

u4Byte
PHY_QueryRFSynReg_8814B(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      eRFPath,
	IN  u4Byte                      RegAddr,
	IN  u4Byte                      BitMask
);

void
PHY_Set_SecCCATH_by_RXANT_8814B(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      ulAntennaRx
);

void
phy_SpurCalibration_8814B(
    IN  HAL_PADAPTER                Adapter
);



#endif //__HAL8814BPHYCFG_H__

