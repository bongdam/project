/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8198FGen.c
	
Abstract:
	Defined RTL8198F HAL Function
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2012-03-23 Filen            Create.	
--*/

#if !defined(__ECOS) && !defined(CPTCFG_CFG80211_MODULE)
#include "HalPrecomp.h"
#else
#include "../../HalPrecomp.h"
#endif

#define VAR_MAPPING(dst,src) \
	u1Byte *data_##dst##_start = &data_##src[0]; \
	u1Byte *data_##dst##_end   = &data_##src[sizeof(data_##src)];

//Test chip
#include "../../../data_AGC_TAB_8198F.c"
#include "../../../data_RadioA_8198F.c"
#include "../../../data_RadioB_8198F.c"
#include "../../../data_RadioC_8198F.c"
#include "../../../data_RadioD_8198F.c"
#include "../../../data_MAC_REG_8198F.c"
#include "../../../data_PHY_REG_8198F.c"


VAR_MAPPING(AGC_TAB_8198F, AGC_TAB_8198F);
VAR_MAPPING(MAC_REG_8198F, MAC_REG_8198F);
VAR_MAPPING(PHY_REG_8198F, PHY_REG_8198F);
VAR_MAPPING(RadioA_8198F, RadioA_8198F);
VAR_MAPPING(RadioB_8198F, RadioB_8198F);
VAR_MAPPING(RadioC_8198F, RadioC_8198F);
VAR_MAPPING(RadioD_8198F, RadioD_8198F);

/////////////////////////////////////////////////


#ifdef CONFIG_8198F_2LAYER
#include "../../../data_AGC_TAB_8198FMP_2layer.c"
#endif
#ifdef CONFIG_8198F_2LAYER
VAR_MAPPING(AGC_TAB_8198FMP_2layer, AGC_TAB_8198FMP_2layer);
#endif

#ifdef CONFIG_8198F_2LAYER
#include "../../../data_RadioA_8198FMP_2layer.c"
#endif
#ifdef CONFIG_8198F_2LAYER
VAR_MAPPING(RadioA_8198FMP_2layer, RadioA_8198FMP_2layer);
#endif

#include "../../../data_PHY_REG_PG_8198Fmp.c"
#include "../../../data_PHY_REG_PG_8198Fmp_Type0.c"
#include "../../../data_PHY_REG_PG_8198Fmp_Type2.c"
#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_PHY_REG_PG_8198Fmp_Type1.c"
#include "../../../data_PHY_REG_PG_8198Fmp_Type3.c"
#include "../../../data_PHY_REG_PG_8198Fmp_Type4.c"
#include "../../../data_PHY_REG_PG_8198Fmp_Type5.c"
#endif

VAR_MAPPING(PHY_REG_PG_8198Fmp, PHY_REG_PG_8198Fmp);
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type0, PHY_REG_PG_8198Fmp_Type0);
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type2, PHY_REG_PG_8198Fmp_Type2);
#if CFG_HAL_HIGH_POWER_EXT_PA
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type1, PHY_REG_PG_8198Fmp_Type1);
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type3, PHY_REG_PG_8198Fmp_Type3);
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type4, PHY_REG_PG_8198Fmp_Type4);
VAR_MAPPING(PHY_REG_PG_8198Fmp_Type5, PHY_REG_PG_8198Fmp_Type5);
#endif

#ifdef TXPWR_LMT_8198F
#include "../../../data_TXPWR_LMT_8198Fmp.c"
#include "../../../data_TXPWR_LMT_8198Fmp_Type0.c"
#include "../../../data_TXPWR_LMT_8198Fmp_Type2.c"

VAR_MAPPING(TXPWR_LMT_8198Fmp,TXPWR_LMT_8198Fmp);
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type0,TXPWR_LMT_8198Fmp_Type0);
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type2,TXPWR_LMT_8198Fmp_Type2);

#if CFG_HAL_HIGH_POWER_EXT_PA
#include "../../../data_TXPWR_LMT_8198Fmp_Type1.c"
#include "../../../data_TXPWR_LMT_8198Fmp_Type3.c"
#include "../../../data_TXPWR_LMT_8198Fmp_Type4.c"
#include "../../../data_TXPWR_LMT_8198Fmp_Type5.c"
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type1,TXPWR_LMT_8198Fmp_Type1);
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type3,TXPWR_LMT_8198Fmp_Type3);
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type4,TXPWR_LMT_8198Fmp_Type4);
VAR_MAPPING(TXPWR_LMT_8198Fmp_Type5,TXPWR_LMT_8198Fmp_Type5);
#endif
#endif

#if 1   //Filen, file below should be updated
#include "../../../data_PHY_REG_MP_8198F.c"
#include "../../../data_rtl8198Ffw.c"

#include "../../../data_TxPowerTrack_AP_8198F.c"
#include "../../../data_TxPowerTrack_AP_8198Fmp.c"
VAR_MAPPING(TxPowerTrack_AP_8198F,TxPowerTrack_AP_8198F);
VAR_MAPPING(TxPowerTrack_AP_8198Fmp,TxPowerTrack_AP_8198Fmp);
#endif

//3 MACDM
//default
#include "../../../data_MACDM_def_high_8198F.c"
#include "../../../data_MACDM_def_low_8198F.c"
#include "../../../data_MACDM_def_normal_8198F.c"
//general
#include "../../../data_MACDM_gen_high_8198F.c"
#include "../../../data_MACDM_gen_low_8198F.c"
#include "../../../data_MACDM_gen_normal_8198F.c"
//txop
#include "../../../data_MACDM_txop_high_8198F.c"
#include "../../../data_MACDM_txop_low_8198F.c"
#include "../../../data_MACDM_txop_normal_8198F.c"
//criteria
#include "../../../data_MACDM_state_criteria_8198F.c"

#if 1   //Filen, file below should be updated
VAR_MAPPING(PHY_REG_MP_8198F, PHY_REG_MP_8198F);
VAR_MAPPING(rtl8198Ffw, rtl8198Ffw);

#endif

//3 MACDM
VAR_MAPPING(MACDM_def_high_8198F, MACDM_def_high_8198F);
VAR_MAPPING(MACDM_def_low_8198F, MACDM_def_low_8198F);
VAR_MAPPING(MACDM_def_normal_8198F, MACDM_def_normal_8198F);

VAR_MAPPING(MACDM_gen_high_8198F, MACDM_gen_high_8198F);
VAR_MAPPING(MACDM_gen_low_8198F, MACDM_gen_low_8198F);
VAR_MAPPING(MACDM_gen_normal_8198F, MACDM_gen_normal_8198F);

VAR_MAPPING(MACDM_txop_high_8198F, MACDM_txop_high_8198F);
VAR_MAPPING(MACDM_txop_low_8198F, MACDM_txop_low_8198F);
VAR_MAPPING(MACDM_txop_normal_8198F, MACDM_txop_normal_8198F);

VAR_MAPPING(MACDM_state_criteria_8198F, MACDM_state_criteria_8198F);



enum rt_status
StopHW8198F(
    IN  HAL_PADAPTER Adapter
)
{

    // TODO: 
    return  RT_STATUS_SUCCESS;
}


enum rt_status
InitPON8198F(
    IN  HAL_PADAPTER Adapter,     
    IN  u4Byte     	ClkSel    
)
{
    RT_TRACE_F( COMP_INIT, DBG_LOUD, ("\n") );

    HAL_RTL_W8(REG_RSV_CTRL, 0x00);

    if(ClkSel == XTAL_CLK_SEL_25M) {
        HAL_RTL_W32(REG_AFE_CTRL5, (HAL_RTL_R32(REG_AFE_CTRL5) & ~(BIT_MASK_REF_SEL<<BIT_SHIFT_REF_SEL)) | BIT_REF_SEL(1));
    } else if (ClkSel == XTAL_CLK_SEL_40M){
        HAL_RTL_W32(REG_AFE_CTRL5, (HAL_RTL_R32(REG_AFE_CTRL5) & ~(BIT_MASK_REF_SEL<<BIT_SHIFT_REF_SEL)) | BIT_REF_SEL(0));
    }	

    if (!HalPwrSeqCmdParsing88XX(Adapter, PWR_CUT_ALL_MSK, PWR_FAB_ALL_MSK,
        PWR_INTF_PCI_MSK, rtl8198F_card_enable_flow))
    {
        RT_TRACE( COMP_INIT, DBG_SERIOUS, ("%s %d, HalPwrSeqCmdParsing init fail!!!\n", __FUNCTION__, __LINE__));
        return RT_STATUS_FAILURE;
    }

    return RT_STATUS_SUCCESS;    
}


enum rt_status	
hal_Associate_8198F(
    HAL_PADAPTER            Adapter,
    BOOLEAN			        IsDefaultAdapter
)
{
    PHAL_INTERFACE              pHalFunc = GET_HAL_INTERFACE(Adapter);
    PHAL_DATA_TYPE              pHalData = _GET_HAL_DATA(Adapter);
    

    //
    //Initialization Related
    //
    pHalData->AccessSwapCtrl        = HAL_ACCESS_SWAP_MEM;
    
    pHalFunc->InitPONHandler        = InitPON8198F;
    pHalFunc->InitMACHandler        = InitMAC88XX_V1;
    pHalFunc->InitFirmwareHandler   = InitMIPSFirmware88XX;
    pHalFunc->InitHCIDMAMemHandler  = InitHCIDMAMem88XX;
    pHalFunc->InitHCIDMARegHandler  = InitHCIDMAReg88XX;    

    pHalFunc->InitMACProtocolHandler    = InitMACProtocol88XX;
    pHalFunc->InitMACSchedulerHandler   = InitMACScheduler88XX;
    pHalFunc->InitMACWMACHandler        = InitMACWMAC88XX;
    pHalFunc->InitMACSysyemCfgHandler   = InitMACSysyemCfg88XX;
    pHalFunc->InitMACTRXHandler         = InitMACTRX88XX;
    pHalFunc->InitMACFunctionHandler    = InitMACFunction88XX;    
        
#if CFG_HAL_SUPPORT_MBSSID        
    pHalFunc->InitMBSSIDHandler     = InitMBSSID88XX_V1;
#endif  //CFG_HAL_SUPPORT_MBSSID
    pHalFunc->InitVAPIMRHandler     = InitVAPIMR88XX;
    pHalFunc->InitLLT_TableHandler  = InitLLT_Table88XX_V1;
    pHalFunc->SetMBIDCAMHandler     = SetMBIDCAM88XX;
#if CFG_HAL_HW_FILL_MACID
    pHalFunc->InitMACIDSearchHandler    = InitMACIDSearch88XX;            
    pHalFunc->CheckHWMACIDResultHandler = CheckHWMACIDResult88XX;            
#endif //CFG_HAL_HW_FILL_MACID


    //
    //Stop Related
    //
#if CFG_HAL_SUPPORT_MBSSID            
    pHalFunc->StopMBSSIDHandler     = StopMBSSID88XX_V1;
#endif  //CFG_HAL_SUPPORT_MBSSID
    pHalFunc->StopHWHandler         = StopHW88XX;
    pHalFunc->StopSWHandler         = StopSW88XX;
    pHalFunc->DisableVXDAPHandler   = DisableVXDAP88XX;
    pHalFunc->StopMBIDCAMHandler    = StopMBIDCAM88XX;


    //
    //ISR Related
    //
    pHalFunc->InitIMRHandler                    = InitIMR88XX;
    pHalFunc->EnableIMRHandler                  = EnableIMR88XX;
    pHalFunc->InterruptRecognizedHandler        = InterruptRecognized88XX;
    pHalFunc->GetInterruptHandler               = GetInterrupt88XX;
    pHalFunc->AddInterruptMaskHandler           = AddInterruptMask88XX;
    pHalFunc->RemoveInterruptMaskHandler        = RemoveInterruptMask88XX;
    pHalFunc->DisableRxRelatedInterruptHandler  = DisableRxRelatedInterrupt88XX;
    pHalFunc->EnableRxRelatedInterruptHandler   = EnableRxRelatedInterrupt88XX;    


    //
    //Tx Related
    //
    pHalFunc->PrepareTXBDHandler            = PrepareTXBD88XX_V1;    
    pHalFunc->FillTxHwCtrlHandler           = FillTxHwCtrl88XX;
    pHalFunc->SyncSWTXBDHostIdxToHWHandler  = SyncSWTXBDHostIdxToHW88XX;
    pHalFunc->TxPollingHandler              = TxPolling88XX;
    pHalFunc->SigninBeaconTXBDHandler       = SigninBeaconTXBD88XX;
    pHalFunc->SetBeaconDownloadHandler      = SetBeaconDownload88XX;
    pHalFunc->FillBeaconDescHandler         = FillBeaconDesc88XX_V1;    
    pHalFunc->GetTxQueueHWIdxHandler        = GetTxQueueHWIdx88XX;
    pHalFunc->MappingTxQueueHandler         = MappingTxQueue88XX_V1;
    pHalFunc->QueryTxConditionMatchHandler  = QueryTxConditionMatch88XX;
    pHalFunc->FillTxDescHandler             = FillTxDesc88XX_V1;
    pHalFunc->FillShortCutTxDescHandler     = FillShortCutTxDesc88XX_V1;

#if CFG_HAL_TX_SHORTCUT
//    pHalFunc->GetShortCutTxDescHandler      = GetShortCutTxDesc88XX;
//    pHalFunc->ReleaseShortCutTxDescHandler  = ReleaseShortCutTxDesc88XX;
    pHalFunc->GetShortCutTxBuffSizeHandler  = GetShortCutTxBuffSize88XX_V1;
    pHalFunc->SetShortCutTxBuffSizeHandler  = SetShortCutTxBuffSize88XX_V1;    
    pHalFunc->CopyShortCutTxDescHandler     = CopyShortCutTxDesc88XX;
    pHalFunc->FillShortCutTxHwCtrlHandler   = FillShortCutTxHwCtrl88XX;    
#if CFG_HAL_HW_TX_SHORTCUT_REUSE_TXDESC        
    pHalFunc->FillHwShortCutTxDescHandler   = FillHwShortCutTxDesc88XX_V1;        
#endif
#endif // CFG_HAL_TX_SHORTCUT
    pHalFunc->ReleaseOnePacketHandler       = ReleaseOnePacket88XX;                  
#if CFG_HAL_HW_TX_SHORTCUT_HDR_CONV
    pHalFunc->ClearHWTXShortcutBufHandler   = ClearHWTXShortcutBufHandler88XX;     
#endif 
#if CFG_HAL_HW_SEQ
    pHalFunc->GetHwSequenceHandler          = GetHwSequenceHandler88XX;     
#endif 

    //
    //Rx Related
    //
    pHalFunc->PrepareRXBDHandler            = PrepareRXBD88XX_V1;
    pHalFunc->QueryRxDescHandler            = QueryRxDesc88XX_V1;
    pHalFunc->UpdateRXBDInfoHandler         = UpdateRXBDInfo88XX;
    pHalFunc->UpdateRXBDHWIdxHandler        = UpdateRXBDHWIdx88XX;
    pHalFunc->UpdateRXBDHostIdxHandler      = UpdateRXBDHostIdx88XX;      

    //
    // General operation
    //
    pHalFunc->GetChipIDMIMOHandler          =   GetChipIDMIMO88XX;
    pHalFunc->SetHwRegHandler               =   SetHwReg88XX;
    pHalFunc->GetHwRegHandler               =   GetHwReg88XX;
    pHalFunc->SetMACIDSleepHandler          =   SetMACIDPauseDriverInfo88XX;
    pHalFunc->GetMACIDQueueInTXPKTBUFHandler=   GetMACIDQueueInTXPKTBUF88XX_V1;
    pHalFunc->CheckHangHandler              =   CheckHang88XX;


    //
    // Timer Related
    //
    pHalFunc->Timer1SecHandler              =   Timer1Sec88XX;
#if CFG_HAL_MACDM
    InitMACDM88XX(Adapter);
    pHalFunc->Timer1SecDMHandler            =   Timer1SecDM88XX;
#endif //CFG_HAL_MACDM


    //
    // Security Related		
    //
    pHalFunc->CAMReadMACConfigHandler       =   CAMReadMACConfig88XX;
    pHalFunc->CAMEmptyEntryHandler          =   CAMEmptyEntry88XX;
    pHalFunc->CAMFindUsableHandler          =   CAMFindUsable88XX;
    pHalFunc->CAMProgramEntryHandler        =   CAMProgramEntry88XX_V1;


    //
    // PHY/RF Related
    //
    pHalFunc->PHYSetCCKTxPowerHandler       = PHYSetCCKTxPower88XX;
    pHalFunc->PHYSetOFDMTxPowerHandler      = PHYSetOFDMTxPower88XX;
    pHalFunc->PHYUpdateBBRFValHandler       = UpdateBBRFVal88XX_AC;
    pHalFunc->PHYSwBWModeHandler            = SwBWMode88XX_8198F;
    // TODO: 8198F Power Tracking should be done
    pHalFunc->TXPowerTrackingHandler        = TXPowerTracking_ThermalMeter_Tmp8198F;
    pHalFunc->PHYSSetRFRegHandler           = PHY_SetRFReg_8198F;    
    pHalFunc->PHYQueryRFRegHandler          = PHY_QueryRFReg_8198F;
    pHalFunc->IsBBRegRangeHandler           = IsBBRegRange88XX_V1;
    

    //
    // Firmware CMD IO related
    //
    pHalData->H2CBufPtr88XX     = 0;
    pHalData->bFWReady          = _FALSE;
    pHalFunc->fill_h2c_cmd_handler             = FillH2CCmd88XX;
    pHalFunc->UpdateHalRAMaskHandler        = UpdateHalRAMask88XX;
    pHalFunc->UpdateHalMSRRPTHandler        = UpdateHalMSRRPT88XX;    
    pHalFunc->SetAPOffloadHandler           = SetAPOffload88XX;
#ifdef AP_PS_Offlaod
    pHalFunc->SetAPPSOffloadHandler         = SetAPPSOffload88XX;
#endif
#ifdef HW_DETECT_PS_OFFLOAD
    pHalFunc->MACIDPauseHandler             = MacidPauseCtrl88XX;
#endif
#ifdef AP_SWPS_OFFLOAD
    pHalFunc->ClearDropIDHandler            = ClearDropID88XX;
    pHalFunc->UpdateMacidSWPSInfoHandler    = UpdateMacidSWPSInfo88XX;
    pHalFunc->MACIDSWPSCtrlHandler          = MACIDSWPSCtrl88XX;
    pHalFunc->AgingFuncOfflaodHandler       = AgingFuncOfflaod88XX;
#endif
    pHalFunc->SetRsvdPageHandler	        = SetRsvdPage88XX;
    pHalFunc->GetRsvdPageLocHandler	        = GetRsvdPageLoc88XX;
    pHalFunc->DownloadRsvdPageHandler	    = DownloadRsvdPage88XX;
    pHalFunc->C2HHandler                    = C2HHandler88XX;
    pHalFunc->C2HPacketHandler              = C2HPacket88XX;        
    pHalFunc->GetTxRPTHandler               = GetTxRPTBuf88XX;
    pHalFunc->SetTxRPTHandler               = SetTxRPTBuf88XX;  
    pHalFunc->init_ddma_handler               = InitDDMA88XX;
#if CFG_HAL_HW_FILL_MACID
    pHalFunc->SetCRC5ToRPTBufferHandler     = SetCRC5ToRPTBuffer88XX;        
#endif //#if CFG_HAL_HW_FILL_MACID

    pHalFunc->DumpRxBDescTestHandler = DumpRxBDesc88XX;
    pHalFunc->DumpTxBDescTestHandler = DumpTxBDesc88XX;
    
    return  RT_STATUS_SUCCESS;    
}


