#ifndef __HAL8822BE_DEF_H__
#define __HAL8822BE_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8822BSDef.h
	
Abstract:
	Defined HAL 8822BE data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric             Create.	
--*/


/*RT_STATUS
InitPON8822BE(
    IN  HAL_PADAPTER    Adapter,
    IN  u4Byte          ClkSel        
);

RT_STATUS
StopHW8822BE(
    IN  HAL_PADAPTER    Adapter
);


RT_STATUS
ResetHWForSurprise8822BE(
    IN  HAL_PADAPTER Adapter
);
*/

enum rt_status	
hal_Associate_8822BS(
	struct rtl8192cd_priv *priv,
	BOOLEAN             IsDefaultAdapter
);

#if (BEAMFORMING_SUPPORT == 1)
#if 0
struct _RT_BEAMFORMING_INFO;

u1Byte
halTxbf8822B_GetNtx(
	struct rtl8192cd_priv *priv
);

VOID
SetBeamformRfMode8822B(
	struct rtl8192cd_priv *priv,
	PRT_BEAMFORMING_INFO 	pBeamformingInfo,
	u1Byte			idx
);

VOID
SetBeamformEnter8822B(
	struct rtl8192cd_priv *priv,
	u1Byte	BFerBFeeIdx
);

VOID
SetBeamformLeave8822B(
	struct rtl8192cd_priv *priv,
	u1Byte	Idx
);

VOID
SetBeamformStatus8822B(
	struct rtl8192cd_priv *priv,
	 u1Byte	Idx
);

VOID
C2HTxBeamformingHandler_8822B(
	struct rtl8192cd_priv *priv,
		pu1Byte			CmdBuf,
		u1Byte			CmdLen
);

VOID
Beamforming_NDPARate_8822B(
	struct rtl8192cd_priv *priv,
	BOOLEAN		Mode,
	u1Byte		BW,
	u1Byte		Rate
);

VOID HW_VAR_HW_REG_TIMER_START_8822B(struct rtl8192cd_priv *priv);

VOID HW_VAR_HW_REG_TIMER_INIT_8822B(struct rtl8192cd_priv *priv, int t);

VOID HW_VAR_HW_REG_TIMER_STOP_8822B(struct rtl8192cd_priv *priv);
#endif
#endif 


#endif  //__HAL8822BE_DEF_H__

