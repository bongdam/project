#ifndef __HAL8814BE_DEF_H__
#define __HAL8814BE_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BEDef.h
	
Abstract:
	Defined HAL 8814BE data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2017-05-10 yllin             Create.	
--*/


/*enum rt_status
InitPON8814BE(
    IN  HAL_PADAPTER    Adapter,
    IN  u4Byte          ClkSel        
);

enum rt_status
StopHW8814BE(
    IN  HAL_PADAPTER    Adapter
);


enum rt_status
ResetHWForSurprise8814BE(
    IN  HAL_PADAPTER Adapter
);
*/

enum rt_status 	
hal_Associate_8814BE(
	struct rtl8192cd_priv *priv,
	BOOLEAN             IsDefaultAdapter
);

#if (BEAMFORMING_SUPPORT == 1)
VOID
SetBeamformInit8814B(
	struct rtl8192cd_priv *priv
	);

VOID
SetBeamformEnter8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				BFerBFeeIdx
	);

VOID
SetBeamformLeave8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	);

VOID
SetBeamformStatus8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	);

void
Beamforming_dym_disable_bf_coeff_8814B(
	struct rtl8192cd_priv *priv,
	u1Byte				   enable
);

VOID Beamforming_NDPARate_8814B(
	struct rtl8192cd_priv *priv,
	BOOLEAN		Mode,
	u1Byte		BW,
	u1Byte		Rate
	);

#if (MU_BEAMFORMING_SUPPORT == 1)
VOID
HalTxbf8814B_ConfigGtab(
	struct rtl8192cd_priv *priv
	);
#endif

u1Byte
halTxbf8814B_GetNtx(
	struct rtl8192cd_priv *priv
);

VOID
C2HTxBeamformingHandler_8814B(
	struct rtl8192cd_priv *priv,
		pu1Byte			CmdBuf,
		u1Byte			CmdLen
);
#endif 


#endif  //__HAL8814BE_DEF_H__

