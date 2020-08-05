#ifndef __HAL8821CPHYCFG_H__
#define __HAL8821CPHYCFG_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8821CPhyCfg.h
	
Abstract:
	Defined HAL 8821C PHY BB setting functions
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric               Create.	
--*/

void 
TXPowerTracking_ThermalMeter_Tmp8821C(
    IN  HAL_PADAPTER    Adapter
);

u4Byte
PHY_QueryRFReg_8821(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      eRFPath,
	IN  u4Byte                      RegAddr,
	IN  u4Byte                      BitMask
);

void
PHY_Set_SecCCATH_by_RXANT_8821C(
	IN  HAL_PADAPTER                Adapter,
	IN  u4Byte                      ulAntennaRx
);

void
phy_SpurCalibration_8821C(
    IN  HAL_PADAPTER                Adapter
);



#endif //__HAL8821CPHYCFG_H__

