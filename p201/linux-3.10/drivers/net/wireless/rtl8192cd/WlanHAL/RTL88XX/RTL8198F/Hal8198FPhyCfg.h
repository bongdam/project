#ifndef __HAL8198FPHYCFG_H__
#define __HAL8198FPHYCFG_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8198FPhyCfg.h
	
Abstract:
	Defined HAL 88XX PHY BB setting functions
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2012-11-14 Eric              Create.	
--*/



// TODO: this function should be modified
void 
TXPowerTracking_ThermalMeter_Tmp8198F(
    IN  HAL_PADAPTER    Adapter
);

u4Byte
PHY_QueryRFReg_8198F(
    IN  HAL_PADAPTER                Adapter,
    IN  u4Byte                      eRFPath,
    IN  u4Byte                      RegAddr,
    IN  u4Byte                      BitMask
);

void 
PHY_SetRFReg_8198F
(
    IN  HAL_PADAPTER                Adapter, 
    IN  u4Byte                      eRFPath,
    IN  u4Byte                      RegAddr,    
    IN  u4Byte                      BitMask,
    IN  u4Byte                      Data
);

void
SwBWMode88XX_8198F(
	IN  HAL_PADAPTER    Adapter,
	IN  u4Byte          bandwidth,
	IN  s4Byte          offset
);




#endif // #ifndef __HAL8198FPHYCFG_H__

