#ifndef __HAL8821C_FIRMWARE_H__
#define __HAL8821C_FIRMWARE_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal88821CFirmware.h
	
Abstract:
	Defined HAL 8821C Firmware data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric            Create.	
--*/

#define ctrlInfoSZ_8821  32


typedef struct _Ctrl_Info_8821_ {
	u1Byte	SGI: 1;
	u1Byte Data_Rate: 7;
	u1Byte	PKT_DROP: 1;    
	u1Byte	TRY_RATE: 1;    
	u1Byte	Rsvd: 1;    
	u1Byte	DATA_BW: 2;    
	u1Byte	PWRSTS: 3;
	u1Byte	RTY_PKT_1SS_ANT_INFO_EN: 4;    
	u1Byte	Rsvd2: 1;    
	u1Byte	GROUP_TABLE_ID: 3;    
	u1Byte	RTY_LOW_RATE_EN: 1;    
	u1Byte	DATA_RTY_LOW_RATE: 7;    
	u1Byte	RTY_LMT_EN: 1;  
	u1Byte	RTS_RT_LOW_RATE: 7;    
	u1Byte	Rsvd3: 1;      
	u1Byte	PKT_TX_ONE_SEL: 1;  
	u1Byte	DATA_RT_LMT: 6;    
	u1Byte	Rsvd4: 8;          
	u1Byte	Rsvd5: 8;          
} Ctrl_Info_8821, *PCtrl_Info_8821;

#endif
