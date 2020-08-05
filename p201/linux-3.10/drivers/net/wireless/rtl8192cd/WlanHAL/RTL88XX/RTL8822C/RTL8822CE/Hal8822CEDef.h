#ifndef __HAL8822CE_DEF_H__
#define __HAL8822CE_DEF_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8822CEDef.h
	
Abstract:
	Defined HAL 8822CE data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-06-25 Eric             Create.	
--*/


/*enum rt_status
InitPON8822CE(
    IN  HAL_PADAPTER    Adapter,
    IN  u4Byte          ClkSel        
);

enum rt_status
StopHW8822CE(
    IN  HAL_PADAPTER    Adapter
);


enum rt_status
ResetHWForSurprise8822CE(
    IN  HAL_PADAPTER Adapter
);
*/

enum rt_status	
hal_Associate_8822CE(
	struct rtl8192cd_priv *priv,
	BOOLEAN             IsDefaultAdapter
);

#if (BEAMFORMING_SUPPORT == 1)
VOID
SetBeamformInit8822C(
	struct rtl8192cd_priv *priv
	);

VOID
SetBeamformEnter8822C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				BFerBFeeIdx
	);

VOID
SetBeamformLeave8822C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	);

VOID
SetBeamformStatus8822C(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	);

void
Beamforming_dym_disable_bf_coeff_8822C(
	struct rtl8192cd_priv *priv,
	u1Byte				   enable
);


#ifdef CONFIG_VERIWAVE_MU_CHECK	
void Beamforming_set_csi_data(
	struct rtl8192cd_priv *priv, 
	int idx, 
	int reg_idx);
#endif

void Beamforming_CSIRate_8822C(
	struct rtl8192cd_priv *priv
);


VOID Beamforming_NDPARate_8822C(
	struct rtl8192cd_priv *priv,
	BOOLEAN		Mode,
	u1Byte		BW,
	u1Byte		Rate
	);
	

#if (MU_BEAMFORMING_SUPPORT == 1)
VOID
HalTxbf8822C_ConfigGtab(
	struct rtl8192cd_priv *priv
	);
#endif

VOID
C2HTxBeamformingHandler_8822C(
	struct rtl8192cd_priv *priv,
		pu1Byte			CmdBuf,
		u1Byte			CmdLen
);
#endif 


#endif  //__HAL8822CE_DEF_H__

