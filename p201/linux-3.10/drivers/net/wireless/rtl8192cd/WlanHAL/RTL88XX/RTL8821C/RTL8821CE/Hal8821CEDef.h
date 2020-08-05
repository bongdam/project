#ifndef __HAL8821CE_DEF_H__
#define __HAL8821CE_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8821CEDef.h
	
Abstract:
	Defined HAL 8821CE data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric             Create.	
--*/


/*RT_STATUS
InitPON8821CE(
    IN  HAL_PADAPTER    Adapter,
    IN  u4Byte          ClkSel        
);

RT_STATUS
StopHW8821CE(
    IN  HAL_PADAPTER    Adapter
);


RT_STATUS
ResetHWForSurprise8821CE(
    IN  HAL_PADAPTER Adapter
);
*/

enum rt_status
hal_Associate_8821CE(
	struct rtl8192cd_priv *priv,
	BOOLEAN             IsDefaultAdapter
);

#if (BEAMFORMING_SUPPORT == 1)
VOID
SetBeamformInit8821C(
	struct rtl8192cd_priv *priv
);

VOID
SetBeamformEnter8821C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				BFerBFeeIdx
);

VOID
SetBeamformLeave8821C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
);

VOID
SetBeamformStatus8821C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
);

VOID
HalTxbf8821C_ConfigGtab(
	struct rtl8192cd_priv *priv
);

VOID
C2HTxBeamformingHandler_8821C(
	struct rtl8192cd_priv *priv,
		pu1Byte			CmdBuf,
		u1Byte			CmdLen
);
#endif 


#endif  //__HAL8821CE_DEF_H__

