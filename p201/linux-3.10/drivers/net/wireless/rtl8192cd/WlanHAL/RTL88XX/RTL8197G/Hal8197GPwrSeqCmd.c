
/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8197GPwrSeqCmd.c
	
Abstract:
	This file includes all kinds of Power Action event for RTL8881A and 
	corresponding hardware configurtions which are released from HW SD.
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2015-04-14 Eric            Create.
	
--*/

#if !defined(__ECOS) && !defined(CPTCFG_CFG80211_MODULE)
#include "HalPrecomp.h"
#else
#include "../../HalPrecomp.h"
#endif


/* 
    drivers should parse below arrays and do the corresponding actions
*/



//3Card Disable Array
WLAN_PWR_CFG rtl8197G_card_disable_flow[RTL8197G_TRANS_ACT_TO_CARDEMU_STEPS+RTL8197G_TRANS_CARDEMU_TO_PDN_STEPS+RTL8197G_TRANS_END_STEPS]=
{
	RTL8197G_TRANS_ACT_TO_CARDEMU
	RTL8197G_TRANS_CARDEMU_TO_CARDDIS
	RTL8197G_TRANS_END
};

//3 Card Enable Array
WLAN_PWR_CFG rtl8197G_card_enable_flow[ ]=
{
    RTL8197G_TRANS_CARDDIS_TO_CARDEMU
	RTL8197G_TRANS_END
};


//3 Enter LPS 
WLAN_PWR_CFG rtl8197G_enter_lps_flow[RTL8197G_TRANS_ACT_TO_LPS_STEPS+RTL8197G_TRANS_END_STEPS]=
{
	//FW behavior
	RTL8197G_TRANS_ACT_TO_LPS	
	RTL8197G_TRANS_END
};

//3 Leave LPS 
WLAN_PWR_CFG rtl8197G_leave_lps_flow[RTL8197G_TRANS_LPS_TO_ACT_STEPS+RTL8197G_TRANS_END_STEPS]=
{
	//FW behavior
	RTL8197G_TRANS_LPS_TO_ACT
	RTL8197G_TRANS_END
};
