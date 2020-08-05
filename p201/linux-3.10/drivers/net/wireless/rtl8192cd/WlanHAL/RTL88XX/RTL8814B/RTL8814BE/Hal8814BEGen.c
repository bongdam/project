/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BEGen.c
	
Abstract:
	Defined RTL8814BE HAL Function
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2017-05-10 yllin             Create.	
--*/

#ifndef __ECOS
#include "HalPrecomp.h"
#else
#include "../../../HalPrecomp.h"
#include "../../../../phydm/phydm_precomp.h" 
#include "../Hal8814BFirmware.h"
#include "../Hal8814HTxDesc.h"
#include "../../../../core/WlanHAL/RTL88XX/RTL8814B/Hal8814HRxDesc_core.h"
#endif

enum rt_status
InitPON8814BE(
    IN  HAL_PADAPTER Adapter,
    IN  u4Byte     	ClkSel        
)
{
    //use halmac
}


enum rt_status
StopHW8814BE(
    IN  HAL_PADAPTER Adapter
)
{
    // TODO:

    return RT_STATUS_SUCCESS;
}

enum rt_status
ResetHWForSurprise8814BE(
    IN  HAL_PADAPTER Adapter
)
{
    // TODO: Filen, necessary to be added code here

    return RT_STATUS_SUCCESS;
}


enum rt_status	
hal_Associate_8814BE(
	 HAL_PADAPTER        Adapter,
    BOOLEAN             IsDefaultAdapter
)
{
    PHAL_INTERFACE              pHalFunc = GET_HAL_INTERFACE(Adapter);
    PHAL_DATA_TYPE              pHalData = _GET_HAL_DATA(Adapter);


    //
    //Initialization Related
    //
    pHalData->AccessSwapCtrl        = HAL_ACCESS_SWAP_MEM;
    pHalFunc->InitPONHandler        = InitPON88XX;
    pHalFunc->InitMACHandler        = InitMAC88XX;
    pHalFunc->InitFirmwareHandler   = InitMIPSFirmware88XX; //halmac have download firmware api can use
    pHalFunc->InitHCIDMAMemHandler  = InitHCIDMAMem88XX;
    pHalFunc->InitHCIDMARegHandler  = InitHCIDMAReg88XX_V1;   
    
#if 0
    pHalFunc->InitMACProtocolHandler    = InitMACProtocol88XX;
    pHalFunc->InitMACSchedulerHandler   = InitMACScheduler88XX;
    pHalFunc->InitMACWMACHandler        = InitMACWMAC88XX;
    pHalFunc->InitMACSysyemCfgHandler   = InitMACSysyemCfg88XX;
    pHalFunc->InitMACTRXHandler         = InitMACTRX88XX;
    pHalFunc->InitMACFunctionHandler    = InitMACFunction88XX; 
#endif
     
#if CFG_HAL_SUPPORT_MBSSID    
    pHalFunc->InitMBSSIDHandler     = InitMBSSID88XX_V2; //kkbomb
#endif  //CFG_HAL_SUPPORT_MBSSID
#ifdef ADDRESS_CAM
	pHalFunc->InitMBIDCAMHandler	= InitADDRCAM88XX; //kkbomb
#endif
    pHalFunc->InitVAPIMRHandler     = InitVAPIMR88XX; //kkbomb
    pHalFunc->InitLLT_TableHandler  = HalGeneralDummy; //should be done in halmac
    pHalFunc->SetMBIDCAMHandler     = HalGeneralDummy; //kkbomb
#ifdef ADDRESS_CAM    
    pHalFunc->SetADDRCAMHandler     = SetADDRCAMEntry88XX; //kkbomb
#endif    
#if CFG_HAL_HW_FILL_MACID
    pHalFunc->InitMACIDSearchHandler    = HalGeneralDummy; //no CRC5 in 8814B
    pHalFunc->CheckHWMACIDResultHandler = CheckHWMACIDResult88XX;            
#endif //CFG_HAL_HW_FILL_MACID
#ifdef MULTI_MAC_CLONE
	pHalFunc->McloneSetMBSSIDHandler	= McloneSetMBSSID88XX_V1; //kkbomb
	pHalFunc->McloneStopMBSSIDHandler	= McloneStopMBSSID88XX_V1; //kkbomb
#endif //MULTI_MAC_CLONE


    //
    //Stop Related
    //
#if CFG_HAL_SUPPORT_MBSSID        
    pHalFunc->StopMBSSIDHandler     = StopMBSSID88XX_V2; //kkbomb
#endif  //CFG_HAL_SUPPORT_MBSSID
    pHalFunc->StopHWHandler         = StopHW88XX;
    pHalFunc->StopSWHandler         = StopSW88XX;
    pHalFunc->DisableVXDAPHandler   = DisableVXDAP88XX;
    pHalFunc->StopMBIDCAMHandler    = HalGeneralDummy; //kkbomb
#ifdef ADDRESS_CAM     
    pHalFunc->ClearADDRCAMHandler    = DelADDRCAMEntry88XX; //kkbomb
#endif
    pHalFunc->ResetHWForSurpriseHandler     = ResetHWForSurprise8814BE;

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
#ifdef CONFIG_RTL_OFFLOAD_DRIVER
    pHalFunc->PrepareTXBDHandler            = PrepareH2D_TXBD88XX; 
    pHalFunc->SigninBeaconTXBDHandler       = rtl88XX_signin_bcn;
    
    pHalFunc->MappingTxQueueHandler         = MappingTxQueue88XX_V2;


#else
    pHalFunc->PrepareTXBDHandler            = PrepareTXBD88XX_V1;    
    pHalFunc->SigninBeaconTXBDHandler       = SigninBeaconTXBD88XX;
    pHalFunc->MappingTxQueueHandler         = MappingTxQueue88XX_V2;
  

#endif
    
    pHalFunc->FillTxHwCtrlHandler           = FillTxHwCtrl88XX;
    pHalFunc->SyncSWTXBDHostIdxToHWHandler  = SyncSWTXBDHostIdxToHW88XX;
    pHalFunc->GetTxQueueHWIdxHandler        = GetTxQueueHWIdx88XX;
    pHalFunc->QueryTxConditionMatchHandler  = QueryTxConditionMatch88XX;

    pHalFunc->TxPollingHandler              = TxPolling88XX;
    pHalFunc->SetBeaconDownloadHandler      = SetBeaconDownload88XX;
    pHalFunc->FillBeaconDescHandler         = FillBeaconDesc88XX_V2; 
    pHalFunc->FillTxDescHandler             = FillTxDesc88XX_V2;
#if CFG_HAL_TX_SHORTCUT //eric-8822
    pHalFunc->FillShortCutTxDescHandler     = FillShortCutTxDesc88XX_V2;    
//    pHalFunc->GetShortCutTxDescHandler      = GetShortCutTxDesc88XX;
//    pHalFunc->ReleaseShortCutTxDescHandler  = ReleaseShortCutTxDesc88XX;
    pHalFunc->GetShortCutTxBuffSizeHandler  = GetShortCutTxBuffSize88XX_V1;
    pHalFunc->SetShortCutTxBuffSizeHandler  = SetShortCutTxBuffSize88XX_V1;
    pHalFunc->CopyShortCutTxDescHandler     = CopyShortCutTxDesc88XX;
    pHalFunc->FillShortCutTxHwCtrlHandler   = FillShortCutTxHwCtrl88XX;    
#if (CFG_HAL_HW_TX_SHORTCUT_REUSE_TXDESC)
    pHalFunc->FillHwShortCutTxDescHandler   = HalGeneralDummy;  //8814B IE is shortcut, use FillHwShortCutIE88XX
#endif
#if (CFG_HAL_SUPPORT_TXDESC_IE)
    pHalFunc->FillHwShortCutIEHandler   = FillHwShortCutIE88XX;  //this function uses IE, if need original txdesc, need to update
#endif

#endif // CFG_HAL_TX_SHORTCUT
    pHalFunc->ReleaseOnePacketHandler       = ReleaseOnePacket88XX;                  

#if CFG_HAL_PWR_REDUCE
	pHalFunc->SetPWRReduceHandler           = SetPWRReduce88XX; 
#endif
    //
    //Rx Related
    //
#ifdef CONFIG_RTL_OFFLOAD_DRIVER
#if defined(CONFIG_PE_ENABLE)
    if(Adapter->pshare->rf_ft_var.manual_pe_enable){
        pHalFunc->PrepareRXBDHandler            = HalGeneralDummy;
        pHalFunc->QueryRxDescHandler            = QueryD2H_RxDesc88XX;
        pHalFunc->UpdateRXBDInfoHandler         = HalGeneralDummy;
        pHalFunc->UpdateRXBDHWIdxHandler        = HalGeneralDummy;
        pHalFunc->UpdateRXBDHostIdxHandler      = HalGeneralDummy; 
    }else
#endif
    {
        pHalFunc->PrepareRXBDHandler            = PrepareRXBD88XX_V1;
        pHalFunc->QueryRxDescHandler            = QueryD2H_RxDesc88XX;
        pHalFunc->UpdateRXBDInfoHandler         = UpdateRXBDInfo88XX;
        pHalFunc->UpdateRXBDHWIdxHandler        = UpdateRXBDHWIdx88XX;
        pHalFunc->UpdateRXBDHostIdxHandler      = UpdateRXBDHostIdx88XX; 
    }

    
       
#else

    pHalFunc->PrepareRXBDHandler            = PrepareRXBD88XX_V1; 
    pHalFunc->QueryRxDescHandler            = QueryRxDesc88XX_V1;
    pHalFunc->UpdateRXBDInfoHandler         = UpdateRXBDInfo88XX;
    pHalFunc->UpdateRXBDHWIdxHandler        = UpdateRXBDHWIdx88XX;
    pHalFunc->UpdateRXBDHostIdxHandler      = UpdateRXBDHostIdx88XX;    
#endif

    //
    // General operation
    //
    pHalFunc->GetChipIDMIMOHandler          =   GetChipIDMIMO88XX;
    pHalFunc->SetHwRegHandler               =   SetHwReg88XX; 
    pHalFunc->GetHwRegHandler               =   GetHwReg88XX; 
    pHalFunc->SetMACIDSleepHandler          =   SetMACIDPauseDriverInfo88XX; //FW need to update, reg changes
	pHalFunc->CheckHangHandler              =   CheckHang88XX; 
    pHalFunc->GetMACIDQueueInTXPKTBUFHandler=   GetMACIDQueueInTXPKTBUF88XX_V2;

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
    pHalFunc->CAMProgramEntryHandler        =   CAMProgramEntry88XX;


    //
    // PHY/RF Related
    //

    pHalFunc->PHYSetCCKTxPowerHandler       = PHYSetCCKTxPower88XX;
    pHalFunc->PHYSetOFDMTxPowerHandler      = PHYSetOFDMTxPower88XX;
    pHalFunc->PHYSwBWModeHandler            = SwBWMode88XX_AC;
    pHalFunc->PHYUpdateBBRFValHandler       = UpdateBBRFVal88XX_AC;
    // TODO: 8814B Power Tracking should be done
    pHalFunc->TXPowerTrackingHandler        = TXPowerTracking_ThermalMeter_Tmp8814B;
    pHalFunc->PHYSSetRFRegHandler           = PHY_SetRFReg_88XX_AC;
    pHalFunc->PHYQueryRFRegHandler          = PHY_QueryRFReg_8814B;
    pHalFunc->PHYSSetRFSynRegHandler        = PHY_SetRFSynReg_88XX_AC;
    pHalFunc->PHYQueryRFSynRegHandler       = PHY_QueryRFSynReg_8814B;
    pHalFunc->IsBBRegRangeHandler           = IsBBRegRange88XX_V1;
    pHalFunc->PHYSetSecCCATHbyRXANT         = PHY_Set_SecCCATH_by_RXANT_8814B;


    //
    // Firmware CMD IO related
    //
    pHalData->H2CBufPtr88XX     = 0;
    pHalData->bFWReady          = _FALSE;
    // TODO: code below should be sync with new 3081 FW
    pHalFunc->fill_h2c_cmd_handler          = FillH2CCmd88XX;
    pHalFunc->UpdateHalRAMaskHandler        = UpdateHalRAMask88XX; //or UpdateHalRAMask8814A??
    pHalFunc->UpdateHalMSRRPTHandler        = UpdateHalMSRRPT88XX;
    pHalFunc->SetAPOffloadHandler           = SetAPOffload88XX;
#if CFG_HAL_WLAN_SUPPORT_FW_CMD
    pHalFunc->FillFwCmdHandler         = FillFWCmd88XX;
#endif
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
#endif    
#ifdef STA_AGING_FUNC_OFFLOAD    
    pHalFunc->AgingFuncOfflaodHandler       = AgingFuncOfflaod88XX;
#endif
    pHalFunc->SetRsvdPageHandler	        = SetRsvdPage88XX;
    pHalFunc->GetRsvdPageLocHandler	        = GetRsvdPageLoc88XX;
    pHalFunc->DownloadRsvdPageHandler	    = DownloadRsvdPage88XX;
    pHalFunc->C2HHandler                    = C2HHandler88XX;
#ifdef CONFIG_RTL_OFFLOAD_DRIVER
    pHalFunc->D2HPacketHandler              = D2HPacket88XX;
#endif
    pHalFunc->C2HPacketHandler              = C2HPacket88XX;
    pHalFunc->GetTxRPTHandler               = GetTxRPTBuf88XX;
    pHalFunc->SetTxRPTHandler               = SetTxRPTBuf88XX;
    pHalFunc->init_ddma_handler             = InitDDMA88XX;
#if CFG_HAL_HW_FILL_MACID
    pHalFunc->SetCRC5ToRPTBufferHandler     = HalGeneralDummy;   //no CRC5 in 8814B
#endif //#if CFG_HAL_HW_FILL_MACID

#if CFG_HAL_HW_TX_SHORTCUT_HDR_CONV
    pHalFunc->ClearHWTXShortcutBufHandler   = ClearHWTXShortcutBufHandler88XX;
    pHalFunc->FindFreeSmhCamHandler         = FindFreeSmhCam88XX;
    pHalFunc->GetSmhCamHandler              = GetSmhCam88XX;

#endif //CFG_HAL_HW_TX_SHORTCUT_HDR_CONV
#if CFG_HAL_HW_SEQ
        pHalFunc->GetHwSequenceHandler      = GetHwSequenceHandler88XX;
#endif //CFG_HAL_HW_SEQ

    pHalFunc->DumpRxBDescTestHandler        = DumpRxBDesc88XX;
    pHalFunc->DumpTxBDescTestHandler        = DumpTxBDesc88XX;

    return  RT_STATUS_SUCCESS;
}


void 
InitMAC8814BE(
    IN  HAL_PADAPTER Adapter
)
{


    
}

#if (BEAMFORMING_SUPPORT == 1)
#define		bMaskDWord					0xffffffff

#if (MU_BEAMFORMING_SUPPORT == 1)
#define BFER_CNT(bfinfo)	((bfinfo)->beamformer_su_cnt + (bfinfo)->beamformer_mu_cnt)
#define BFEE_CNT(bfinfo)	((bfinfo)->beamformee_su_cnt + (bfinfo)->beamformee_mu_cnt)
#else
#define BFER_CNT(bfinfo)	((bfinfo)->beamformer_su_cnt)
#define BFEE_CNT(bfinfo)	((bfinfo)->beamformee_su_cnt)
#endif

u1Byte
halTxbf8814B_GetNtx(
	struct rtl8192cd_priv *priv
	)
{
	u1Byte			Ntx = 0;

	if(get_rf_mimo_mode(priv) == RF_4T4R)
		Ntx = 3;
	else if(get_rf_mimo_mode(priv) == RF_3T3R)
		Ntx = 2;
	else if(get_rf_mimo_mode(priv) == RF_2T2R)
		Ntx = 1;
	else
		Ntx = 1;

	return Ntx;

}


u1Byte
halTxbf8814B_GetNrx(
	IN PVOID			p_dm_void
	)
{
	struct dm_struct*	p_dm_odm = (struct dm_struct*)p_dm_void;
	u1Byte			Nrx = 0;

	if (p_dm_odm->rf_type == RF_4T4R)
		Nrx = 3;
	else if (p_dm_odm->rf_type == RF_3T3R)
		Nrx = 2;
	else if (p_dm_odm->rf_type == RF_2T2R)
		Nrx = 1;
	else if (p_dm_odm->rf_type == RF_2T3R)
		Nrx = 2;
	else if (p_dm_odm->rf_type == RF_2T4R)
		Nrx = 3;
	else if (p_dm_odm->rf_type == RF_1T1R)
		Nrx = 0;
	else if (p_dm_odm->rf_type == RF_1T2R)
		Nrx = 1;
	else
		Nrx = 0;

	return Nrx;
	
}

/***************SU & MU BFee Entry********************/
VOID
halTxbf8814B_RfMode(
	IN PVOID			p_dm_void,
	IN	struct _RT_BEAMFORMING_INFO*	pBeamformingInfo,
	IN	u1Byte					idx
	)
{
	struct dm_struct*	p_dm_odm = (struct dm_struct*)p_dm_void;
	u1Byte				i;
	PRT_BEAMFORMING_ENTRY	BeamformeeEntry;

	if (idx < BEAMFORMEE_ENTRY_NUM)
		BeamformeeEntry = &pBeamformingInfo->BeamformeeEntry[idx];
	else
		return;

	if (p_dm_odm->rf_type == RF_1T1R)
		return;

	if ((pBeamformingInfo->beamformee_su_cnt > 0) 
#if (MU_BEAMFORMING_SUPPORT == 1)		
		|| (pBeamformingInfo->beamformee_mu_cnt > 0)
#endif		
		) {
		for (i = RF_PATH_A; i <= RF_PATH_D; i++) {
			odm_set_rf_reg(p_dm_odm, i, 0xEF, BIT19, 0x1); /*RF Mode table write enable*/
			odm_set_rf_reg(p_dm_odm, i, 0x33, 0xF, 3); /*Select RX mode*/
			odm_set_rf_reg(p_dm_odm, i, 0x3E, 0xfffff, 0x00036); /*Set Table data*/	
			odm_set_rf_reg(p_dm_odm, i, 0x3F, 0xfffff, 0x5AFCE); /*Set Table data*/
			odm_set_rf_reg(p_dm_odm, i, 0xEF, BIT19, 0x0); /*RF Mode table write disable*/
		}
		odm_set_bb_reg(p_dm_odm, REG_BB_TXBF_ANT_SET_BF1, 0xffffffff, 0xe0000433);
		odm_set_bb_reg(p_dm_odm, REG_BB_TXBF_ANT_SET_BF0, 0xffffffff, 0x00000433);
	}
}
#if 0
VOID
halTxbf8814B_DownloadNDPA(
	IN	PADAPTER			Adapter,
	IN	u1Byte				Idx
	)
{
	u1Byte			u1bTmp = 0, tmpReg422 = 0;
	u1Byte			BcnValidReg = 0, count = 0, DLBcnCount = 0;
	u2Byte			Head_Page = 0x7FE;
	BOOLEAN			bSendBeacon = FALSE;
	HAL_DATA_TYPE	*pHalData = GET_HAL_DATA(Adapter);
	u2Byte			TxPageBndy = LAST_ENTRY_OF_TX_PKT_BUFFER_8814A; /*default reseved 1 page for the IC type which is undefined.*/
	PRT_BEAMFORMING_INFO	pBeamInfo = GET_BEAMFORM_INFO(Adapter);
	PRT_BEAMFORMEE_ENTRY	pBeamEntry = pBeamInfo->BeamformeeEntry+Idx;

	pHalData->bFwDwRsvdPageInProgress = TRUE;
	Adapter->HalFunc.GetHalDefVarHandler(Adapter, HAL_DEF_TX_PAGE_BOUNDARY, (pu2Byte)&TxPageBndy);
	
	/*Set REG_CR bit 8. DMA beacon by SW.*/
	u1bTmp = PlatformEFIORead1Byte(Adapter, REG_CR_8814A+1);
	PlatformEFIOWrite1Byte(Adapter,  REG_CR_8814A+1, (u1bTmp|BIT0));


	/*Set FWHW_TXQ_CTRL 0x422[6]=0 to tell Hw the packet is not a real beacon frame.*/
	tmpReg422 = PlatformEFIORead1Byte(Adapter, REG_FWHW_TXQ_CTRL_8814A+2);
	PlatformEFIOWrite1Byte(Adapter, REG_FWHW_TXQ_CTRL_8814A+2,  tmpReg422&(~BIT6));

	if (tmpReg422 & BIT6) {
		RT_TRACE(COMP_INIT, DBG_LOUD, ("SetBeamformDownloadNDPA_8814A(): There is an Adapter is sending beacon.\n"));
		bSendBeacon = TRUE;
	}

	/*0x204[11:0]	Beacon Head for TXDMA*/
	PlatformEFIOWrite2Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A, Head_Page);
	
	do {		
		/*Clear beacon valid check bit.*/
		BcnValidReg = PlatformEFIORead1Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A+1);
		PlatformEFIOWrite1Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A+1, (BcnValidReg|BIT7));
		
		/*download NDPA rsvd page.*/
		if (pBeamEntry->BeamformEntryCap & BEAMFORMER_CAP_VHT_SU)
			Beamforming_SendVHTNDPAPacket(pDM_Odm, pBeamEntry->MacAddr, pBeamEntry->AID, pBeamEntry->SoundBW, BEACON_QUEUE);
		else 
			Beamforming_SendHTNDPAPacket(pDM_Odm, pBeamEntry->MacAddr, pBeamEntry->SoundBW, BEACON_QUEUE);
	
		/*check rsvd page download OK.*/
		BcnValidReg = PlatformEFIORead1Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A + 1);
		count = 0;
		while (!(BcnValidReg & BIT7) && count < 20) {
			count++;
			delay_us(10);
			BcnValidReg = PlatformEFIORead1Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A+2);
		}
		DLBcnCount++;
	} while (!(BcnValidReg & BIT7) && DLBcnCount < 5);
	
	if (!(BcnValidReg & BIT0))
		RT_DISP(FBEAM, FBEAM_ERROR, ("%s Download RSVD page failed!\n", __func__));

	/*0x204[11:0]	Beacon Head for TXDMA*/
	PlatformEFIOWrite2Byte(Adapter, REG_FIFOPAGE_CTRL_2_8814A, TxPageBndy);

	/*To make sure that if there exists an adapter which would like to send beacon.*/
	/*If exists, the origianl value of 0x422[6] will be 1, we should check this to*/
	/*prevent from setting 0x422[6] to 0 after download reserved page, or it will cause */
	/*the beacon cannot be sent by HW.*/
	/*2010.06.23. Added by tynli.*/
	if (bSendBeacon)
		PlatformEFIOWrite1Byte(Adapter, REG_FWHW_TXQ_CTRL_8814A+2, tmpReg422);

	/*Do not enable HW DMA BCN or it will cause Pcie interface hang by timing issue. 2011.11.24. by tynli.*/
	/*Clear CR[8] or beacon packet will not be send to TxBuf anymore.*/
	u1bTmp = PlatformEFIORead1Byte(Adapter, REG_CR_8814A+1);
	PlatformEFIOWrite1Byte(Adapter, REG_CR_8814A+1, (u1bTmp&(~BIT0)));

	pBeamEntry->BeamformEntryState = BEAMFORMING_ENTRY_STATE_PROGRESSED;

	pHalData->bFwDwRsvdPageInProgress = FALSE;
}

VOID
halTxbf8814B_FwTxBFCmd(
	IN	PADAPTER	Adapter
	)
{
	u1Byte	Idx, Period = 0;
	u1Byte	PageNum0 = 0xFF, PageNum1 = 0xFF;
	u1Byte	u1TxBFParm[3] = {0};

	PMGNT_INFO				pMgntInfo = &(Adapter->MgntInfo);
	PRT_BEAMFORMING_INFO	pBeamInfo = GET_BEAMFORM_INFO(Adapter);

	for (Idx = 0; Idx < BEAMFORMEE_ENTRY_NUM; Idx++) {
		if (pBeamInfo->BeamformeeEntry[Idx].bUsed && pBeamInfo->BeamformeeEntry[Idx].BeamformEntryState == BEAMFORMING_ENTRY_STATE_PROGRESSED) {
			if (pBeamInfo->BeamformeeEntry[Idx].bSound) {
				PageNum0 = 0xFE;
				PageNum1 = 0x07;
				Period = (u1Byte)(pBeamInfo->BeamformeeEntry[Idx].SoundPeriod);
			} else if (PageNum0 == 0xFF) {
				PageNum0 = 0xFF; /*stop sounding*/
				PageNum1 = 0x0F;
			}
		}
	}

	u1TxBFParm[0] = PageNum0;
	u1TxBFParm[1] = PageNum1;
	u1TxBFParm[2] = Period;
	FillH2CCmd(Adapter, PHYDM_H2C_TXBF, 3, u1TxBFParm);
	
	RT_DISP(FBEAM, FBEAM_FUN, ("@%s End, PageNum0 = 0x%x, PageNum1 = 0x%x Period = %d", __func__, PageNum0, PageNum1, Period));
}
#endif

VOID
SetBeamformInit8814B(
	struct rtl8192cd_priv *priv
	)
{
	struct dm_struct*	p_dm_odm = ODMPTR;
	u1Byte		u1bTmp;
	struct _RT_BEAMFORMING_INFO* pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	int i;
	
	odm_set_bb_reg(p_dm_odm, 0x14c0 , BIT16, 1); /*Enable P1 aggr new packet according to P0 transfer time*/
	
	/*MU Retry Limit*/
	if(priv->pshare->rf_ft_var.mu_retry > 15)
		priv->pshare->rf_ft_var.mu_retry = 15;
	
	if(priv->pshare->rf_ft_var.mu_retry == 0)
		priv->pshare->rf_ft_var.mu_retry = 10;
	
	for(i = 0; i < BEAMFORMEE_ENTRY_NUM; i++) { 		
#if (MU_BEAMFORMING_SUPPORT == 1)		
		pBeamformingInfo->BeamformeeEntry[i].mu_reg_index = 0xFF;
#endif
		pBeamformingInfo->BeamformeeEntry[i].su_reg_index = 0xFF;
	}
	
	for(i = 0; i < BEAMFORMER_ENTRY_NUM; i++) { 			
#if (MU_BEAMFORMING_SUPPORT == 1)		
		pBeamformingInfo->BeamformerEntry[i].is_mu_ap = FALSE;
#endif
		pBeamformingInfo->BeamformerEntry[i].su_reg_index = 0xFF;
	}
			
	odm_set_bb_reg(p_dm_odm, 0x14c0 , BIT15|BIT14|BIT13|BIT12, priv->pshare->rf_ft_var.mu_retry); 
	
	odm_set_bb_reg(p_dm_odm, 0x14c0 , BIT7, 0); /*Disable Tx MU-MIMO until sounding done*/	
	odm_set_bb_reg(p_dm_odm, 0x14c0 , 0x3F, 0); /* Clear validity of MU STAs */
	odm_write_1byte(p_dm_odm, 0x167c , 0x70); /*MU-MIMO Option as default value*/
	odm_write_2byte(p_dm_odm, 0x1680 , 0); /*MU-MIMO Control as default value*/
	
	/* Set MU NDPA rate & BW source */
	/* 0x42C[30] = 1 (0: from Tx desc, 1: from 0x45F) */
	u1bTmp = odm_read_1byte(p_dm_odm, REG_TXBF_CTRL_8814B + 3);
	odm_write_1byte(p_dm_odm, REG_TXBF_CTRL_8814B + 3, (u1bTmp|BIT6)); //eric-mu
	/* 0x45F[7:0] = 0x10 (Rate=OFDM_6M, BW20) */
	odm_write_1byte(p_dm_odm, REG_NDPA_OPT_CTRL_8814B, 0x10);
	
	/*Temp Settings*/
	odm_set_bb_reg(p_dm_odm, 0x6DC , 0x7F000000, 0x44); /*STA2's CSI rate is fixed at 6M*/
	
	/*Grouping bitmap parameters*/
	/*
	odm_set_bb_reg(p_dm_odm, 0x1C80 , bMaskDWord, 0x314c314c); 
	odm_set_bb_reg(p_dm_odm, 0x1C84 , bMaskDWord, 0x30cc30cc); 
	odm_set_bb_reg(p_dm_odm, 0x1C88 , bMaskDWord, 0x350c350c); 
	odm_set_bb_reg(p_dm_odm, 0x1C8C , bMaskDWord, 0x328c328c); 
		
	odm_set_bb_reg(p_dm_odm, 0x1C90 , bMaskDWord, 0x314c314c); 
		
	if(AC_SIGMA_MODE == AC_SIGMA_APUT) 
	odm_set_bb_reg(p_dm_odm, 0x1C94 , bMaskDWord, 0xafffafff); //Force MU Tx for 11ac logo r2
	else
	odm_set_bb_reg(p_dm_odm, 0x1C94 , bMaskDWord, 0x3a0c3a0c);
		
	odm_set_bb_reg(p_dm_odm, 0x1C98 , bMaskDWord, 0x350c350c); 
	odm_set_bb_reg(p_dm_odm, 0x1C9C , bMaskDWord, 0x328c328c); 
	
	odm_set_bb_reg(p_dm_odm, 0x1CAC , bMaskDWord, 0x328c328c); 
	*/
	
#if (MU_BEAMFORMING_SUPPORT == 1)
	/* Init HW variable */
	pBeamformingInfo->RegMUTxCtrl = odm_read_4byte(p_dm_odm, 0x14c0);
#endif
	
	odm_set_bb_reg(p_dm_odm, 0x19E0 , BIT5|BIT4, 3); /*8814B grouping method*/
	
	if (p_dm_odm->rf_type == RF_4T4R) { /*2T2R*/
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s: rf_type is 4T4R\n", __func__);
		if (priv->pshare->CurrentChannelBW == CHANNEL_WIDTH_80_80)
			config_phydm_trx_80p80_8814b(ODMPTR, BB_PATH_ABCD, BB_PATH_ABCD, priv->pshare->txsc_20);
		else
		config_phydm_trx_mode_8814b(p_dm_odm, BB_PATH_ABCD, BB_PATH_ABCD);
	}
}

VOID
SetBeamformEnter8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				BFerBFeeIdx
	)
{
	struct dm_struct*	p_dm_odm = ODMPTR;
	u1Byte					i = 0;
	u1Byte					BFerIdx = (BFerBFeeIdx & 0xF0)>>4;
	u1Byte					BFeeIdx = (BFerBFeeIdx & 0xF);
	u2Byte					CSI_Param = 0;
	struct _RT_BEAMFORMING_INFO* pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	PRT_BEAMFORMING_ENTRY	pBeamformeeEntry;
	struct _RT_BEAMFORMER_ENTRY*	pBeamformerEntry;
	u2Byte					value16, STAid = 0;
	u1Byte					Nc_index = 0, Nr_index = 0, grouping = 0, codebookinfo = 0, coefficientsize = 0;
#if (MU_BEAMFORMING_SUPPORT == 1)	
	u4Byte					gid_valid, user_position_l, user_position_h;
#endif	
	u1Byte					u1bTmp;
	u4Byte					u4bTmp;
	u1Byte					h2c_content[6] = {0};
	u4Byte					flags;
	struct halmac_su_bfer_init_para su_bfer_para, *su_bfer = &su_bfer_para;
	struct halmac_mu_bfer_init_para mu_bfer_para, *mu_bfer = &mu_bfer_para;
	struct halmac_mu_bfee_init_para mu_bfee_para, *mu_bfee = &mu_bfee_para;
	
	SAVE_INT_AND_CLI(flags);
	//RT_DISP(FBEAM, FBEAM_FUN, ("%s: BFerBFeeIdx=%d, BFerIdx=%d, BFeeIdx=%d\n", __func__, BFerBFeeIdx, BFerIdx, BFeeIdx));
#if (MU_BEAMFORMING_SUPPORT == 1)	
	PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s] BFerBFeeIdx=%d, BFerIdx=%d, BFeeIdx=%d, beamformee_su_cnt=%d, beamformee_mu_cnt=%d, beamformee_su_reg_maping=%d, beamformee_mu_reg_maping=%d\n", __func__, BFerBFeeIdx, BFerIdx, BFeeIdx, pBeamformingInfo->beamformee_su_cnt, pBeamformingInfo->beamformee_mu_cnt,pBeamformingInfo->beamformee_su_reg_maping, pBeamformingInfo->beamformee_mu_reg_maping);
#endif
	/*************SU BFer Entry Init*************/
	if ((pBeamformingInfo->beamformer_su_cnt > 0) && (BFerIdx < BEAMFORMER_ENTRY_NUM)) {
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s]SU BFer Entry Init\n", __func__);
		pBeamformerEntry = &pBeamformingInfo->BeamformerEntry[BFerIdx];
		pBeamformerEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDING;
#if (MU_BEAMFORMING_SUPPORT == 1)		
		pBeamformerEntry->is_mu_ap = FALSE;
#endif
		/*Sounding protocol control*/
		if (BFER_CNT(pBeamformingInfo) == 1)
			GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_sounding(priv->pHalmac_adapter, HAL_BFEE, HALMAC_OFDM6);
				
		/*MAC address/Partial AID of Beamformer*/
		su_bfer->userid = pBeamformerEntry->su_reg_index;
		su_bfer->paid = pBeamformerEntry->P_AID;
		memcpy(&su_bfer->bfer_address, pBeamformerEntry->MacAddr, 6);

		/*CSI report parameters of Beamformer*/
		Nc_index = halTxbf8814B_GetNrx(p_dm_odm);	/*for 8814A Nrx = 3(4 Ant), min=0(1 Ant)*/
		Nr_index = pBeamformerEntry->NumofSoundingDim;	/*0x718[7] = 1 use Nsts, 0x718[7] = 0 use reg setting. as Bfee, we use Nsts, so Nr_index don't care*/
		
		grouping = 0;

		/*for ac = 1, for n = 3*/
		if (pBeamformerEntry->BeamformEntryCap & BEAMFORMEE_CAP_VHT_SU)
			codebookinfo = 1;	
		else if (pBeamformerEntry->BeamformEntryCap & BEAMFORMEE_CAP_HT_EXPLICIT)
			codebookinfo = 3;	

		coefficientsize = 3;

		CSI_Param = (u2Byte)((coefficientsize<<10)|(codebookinfo<<8)|(grouping<<6)|(Nr_index<<3)|(Nc_index));

		su_bfer->csi_para = CSI_Param;

		/*init beamformer entry*/
		GET_MACHALAPI_INTERFACE(priv)->halmac_su_bfer_entry_init(priv->pHalmac_adapter, su_bfer);
		
		pBeamformerEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDED;
	}

	/*************SU BFee Entry Init*************/
	if ((pBeamformingInfo->beamformee_su_cnt > 0) && (BFeeIdx < BEAMFORMEE_ENTRY_NUM)) {
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s]SU BFee Entry Init\n", __func__);
		pBeamformeeEntry = &pBeamformingInfo->BeamformeeEntry[BFeeIdx];
		if((pBeamformeeEntry->BeamformEntryCap & BEAMFORMER_CAP_VHT_SU) && 
			!(pBeamformeeEntry->BeamformEntryCap & BEAMFORM_CAP_VHT_MU_BFER) &&
			pBeamformeeEntry->su_reg_index == 0xFF)
		{
			pBeamformeeEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDING;
	#if (MU_BEAMFORMING_SUPPORT == 1)		
			pBeamformeeEntry->is_mu_sta = FALSE;
	#endif
	
#if (MU_BEAMFORMING_SUPPORT == 1)
			phydm_txbf_rfmode(p_dm_odm, pBeamformingInfo->beamformee_su_cnt, pBeamformingInfo->beamformee_mu_cnt);
#else
			phydm_txbf_rfmode(p_dm_odm, pBeamformingInfo->beamformee_su_cnt, 0);
#endif		
			//if (phydm_acting_determine(p_dm_odm, phydm_acting_as_ibss))
				//STAid = pBeamformeeEntry->MacId;
			//else 
				STAid = pBeamformeeEntry->P_AID;

			for (i = 0; i < MAX_NUM_BEAMFORMEE_SU; i++) {
				if ((pBeamformingInfo->beamformee_su_reg_maping & BIT(i)) == 0) {
					pBeamformingInfo->beamformee_su_reg_maping |= BIT(i);
					pBeamformeeEntry->su_reg_index = i;
					break;
				}
			}
		
			/*enable NDPA transmission & enable NDPA interrupt*/
			if (BFEE_CNT(pBeamformingInfo) == 1)
				GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_sounding(priv->pHalmac_adapter, HAL_BFER, HALMAC_OFDM6);

			/*init beamformee entry*/
			GET_MACHALAPI_INTERFACE(priv)->halmac_su_bfee_entry_init(priv->pHalmac_adapter, pBeamformeeEntry->su_reg_index, STAid);

			pBeamformeeEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDED;
			Beamforming_Notify(p_dm_odm->priv);
		}
	}

#if (MU_BEAMFORMING_SUPPORT == 1)
	/*************MU BFer Entry Init*************/
	if ((pBeamformingInfo->beamformer_mu_cnt > 0) && (BFerIdx < BEAMFORMER_ENTRY_NUM)) {
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s]MU BFer Entry Init\n", __func__);
		pBeamformerEntry = &pBeamformingInfo->BeamformerEntry[BFerIdx];
		if(pBeamformerEntry->BeamformEntryCap & BEAMFORM_CAP_VHT_MU_BFEE)
		{
			pBeamformerEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDING;
			pBeamformingInfo->mu_ap_index = BFerIdx;
			pBeamformerEntry->is_mu_ap = TRUE;
			for (i = 0; i < 8; i++)
				pBeamformerEntry->gid_valid[i] = 0;
			for (i = 0; i < 16; i++)
				pBeamformerEntry->user_position[i] = 0;
		
			/*Sounding protocol control*/
			if (BFER_CNT(pBeamformingInfo) == 1)
				GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_sounding(priv->pHalmac_adapter, HAL_BFEE, HALMAC_OFDM6);

			/* MAC address */
			memcpy(&mu_bfer->bfer_address, pBeamformerEntry->MacAddr, 6);

			/* Set AID, partial AID */
			mu_bfer->paid = pBeamformerEntry->P_AID;
			mu_bfer->my_aid = pBeamformerEntry->AID;

			/*CSI report parameters of Beamformer*/
			Nc_index = halTxbf8814B_GetNrx(p_dm_odm);	/* Depend on RF type */
			Nr_index = 1;	/*0x718[7] = 1 use Nsts, 0x718[7] = 0 use reg setting. as Bfee, we use Nsts, so Nr_index don't care*/
			grouping = 0; /*no grouping*/
			codebookinfo = 1; /*7 bit for psi, 9 bit for phi*/
			coefficientsize = 0; /*This is nothing really matter*/ 
			CSI_Param = (u2Byte)((coefficientsize<<10)|(codebookinfo<<8)|(grouping<<6)|(Nr_index<<3)|(Nc_index));
			
			mu_bfer->csi_para = CSI_Param;
			mu_bfer->csi_length_sel = 0; /*3895 bytes*/

			/*init beamformer entry*/
			GET_MACHALAPI_INTERFACE(priv)->halmac_mu_bfer_entry_init(priv->pHalmac_adapter, mu_bfer);

			/* Set 80us for leaving ndp_rx_standby_state */
			/*odm_write_1byte(p_dm_odm, 0x71B, 0x50);*/
		
			/* Set 0x6A0[14] = 1 to accept action_no_ack */
			u1bTmp = odm_read_1byte(p_dm_odm, REG_RXFLTMAP0_8814B+1);
			u1bTmp |= 0x40;
			odm_write_1byte(p_dm_odm, REG_RXFLTMAP0_8814B+1, u1bTmp);
			/* Set 0x6A2[5:4] = 1 to NDPA and BF report poll */
			u1bTmp = odm_read_1byte(p_dm_odm, REG_RXFLTMAP1_8814B);
			u1bTmp |= 0x30;
			odm_write_1byte(p_dm_odm, REG_RXFLTMAP1_8814B, u1bTmp);
		
			pBeamformerEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDED;
		}
	}
	

	/*************MU BFee Entry Init*************/
	if ((pBeamformingInfo->beamformee_mu_cnt > 0) && (BFeeIdx < BEAMFORMEE_ENTRY_NUM)) {
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s]MU BFee Entry Init, RegMUTxCtrl=0x%x\n", __func__, pBeamformingInfo->RegMUTxCtrl);
		pBeamformeeEntry = &pBeamformingInfo->BeamformeeEntry[BFeeIdx];
		if((pBeamformeeEntry->BeamformEntryCap & BEAMFORM_CAP_VHT_MU_BFER) && pBeamformeeEntry->mu_reg_index == 0xFF)
		{
			pBeamformeeEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDING;
			pBeamformeeEntry->is_mu_sta = TRUE;

			pBeamformeeEntry->mu_reg_index = 0xFF;

			/*due to 8814b hw bug, should use entry in reverse order*/
			for (i = MAX_NUM_BEAMFORMEE_MU; i > 0; i--) {
				if ((pBeamformingInfo->beamformee_mu_reg_maping & BIT(i - 1)) == 0) {
					pBeamformingInfo->beamformee_mu_reg_maping |= BIT(i - 1);
					pBeamformeeEntry->mu_reg_index = i - 1;
					break;
				}
			}

			if (pBeamformeeEntry->mu_reg_index == 0xFF) {
				/* There is no valid bit in beamformee_mu_reg_maping */
				panic_printk("%s: ERROR! There is no valid bit in beamformee_mu_reg_maping!\n", __func__);
				//RT_DISP(FBEAM, FBEAM_FUN, ("%s: ERROR! There is no valid bit in beamformee_mu_reg_maping!\n", __func__));
				RESTORE_INT(flags);
				return;
			}
			
			/*User position table*/
			gid_valid = 0x2;
			
			switch (pBeamformeeEntry->mu_reg_index) {
			case 0:
				user_position_l = 0x0;
				user_position_h = 0x0;
				break;
			case 1:
				user_position_l = 0x4;
				user_position_h = 0x0;
				break;
			case 2:
				user_position_l = 0x8;
				user_position_h = 0x0;
				break;
			case 3:
				user_position_l = 0xc;
				user_position_h = 0x0;
				break;
			}

			for (i = 0; i < 8; i++) {
				if (i < 4) {
					pBeamformeeEntry->gid_valid[i] = (u1Byte)(gid_valid & 0xFF);
					gid_valid = (gid_valid >> 8);
				} else
					pBeamformeeEntry->gid_valid[i] = 0;
			}
			for (i = 0; i < 16; i++) {
				if (i < 4)
					pBeamformeeEntry->user_position[i] = (u1Byte)((user_position_l >>(i*8)) & 0xFF);
				else if (i < 8)
					pBeamformeeEntry->user_position[i] = (u1Byte)((user_position_h >>((i-4)*8)) & 0xFF);
				else
					pBeamformeeEntry->user_position[i] = 0;
			}

			/*Sounding protocol control*/
			if(AC_SIGMA_MODE == AC_SIGMA_APUT)
				GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_sounding(priv->pHalmac_adapter, HAL_BFER, HALMAC_VHT_NSS1_MCS0);
			else if (BFEE_CNT(pBeamformingInfo) == 1)
				GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_sounding(priv->pHalmac_adapter, HAL_BFER, HALMAC_OFDM6);
			
			/*select MU STA table*/
			mu_bfee->userid = pBeamformeeEntry->mu_reg_index + 2;
			mu_bfee->paid = pBeamformeeEntry->P_AID;
			mu_bfee->user_position_l = user_position_l;
			mu_bfee->user_position_h = user_position_h;
			mu_bfee->user_position_l_1 = 0;
			mu_bfee->user_position_h_1 = 0;

			GET_MACHALAPI_INTERFACE(priv)->halmac_mu_bfee_entry_init(priv->pHalmac_adapter, mu_bfee);
			
			pBeamformingInfo->RegMUTxCtrl &= ~(BIT8|BIT9|BIT10);
			pBeamformingInfo->RegMUTxCtrl |= (pBeamformeeEntry->mu_reg_index << 8)&(BIT8|BIT9|BIT10);

			/*set validity of MU STAs*/		
			pBeamformingInfo->RegMUTxCtrl &= 0xFFFFFFC0;
			pBeamformingInfo->RegMUTxCtrl |= pBeamformingInfo->beamformee_mu_reg_maping&0x3F;
			odm_write_4byte(p_dm_odm, 0x14c0, pBeamformingInfo->RegMUTxCtrl);

			PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, RegMUTxCtrl = 0x%x, user_position_l = 0x%x, user_position_h = 0x%x\n", 
				__func__, pBeamformingInfo->RegMUTxCtrl, user_position_l, user_position_h);

			/* Set 0x6A0[14] = 1 to accept action_no_ack */
			u1bTmp = odm_read_1byte(p_dm_odm, REG_RXFLTMAP0_8814B+1);
			u1bTmp |= 0x40;
			odm_write_1byte(p_dm_odm, REG_RXFLTMAP0_8814B+1, u1bTmp);
			/* End of MAC registers setting */
			
			phydm_txbf_rfmode(p_dm_odm, pBeamformingInfo->beamformee_su_cnt, pBeamformingInfo->beamformee_mu_cnt);
			pBeamformeeEntry->HwState = BEAMFORM_ENTRY_HW_STATE_ADDED;

			/*Special for plugfest*/
			delay_ms(50); /* wait for 4-way handshake ending*/
	
			issue_action_GROUP_ID(p_dm_odm->priv, BFeeIdx);

			Beamforming_Notify(priv);

			h2c_content[0] = 1;
			h2c_content[1] = pBeamformeeEntry->mu_reg_index;
			h2c_content[2] = pBeamformeeEntry->MacId;
			h2c_content[3] = 0; // 0: support 256QAM, 1: not support 256QAM
			odm_fill_h2c_cmd(p_dm_odm, PHYDM_H2C_MU, 4, h2c_content);
#ifdef CONFIG_WLAN_HAL_8822BE
			if (GET_CHIP_VER(priv) == VERSION_8822B) {
				u4Byte ctrl_info_offset, index;
				/*Set Ctrl Info*/
				odm_write_2byte(p_dm_odm, 0x140, 0x660);
				ctrl_info_offset = 0x8000 + 32 * pBeamformeeEntry->MacId;
				/*Reset Ctrl Info*/
				for (index = 0; index < 8; index++)
					odm_write_4byte(p_dm_odm, ctrl_info_offset + index*4, 0);
			
				odm_write_4byte(p_dm_odm, ctrl_info_offset, (pBeamformeeEntry->mu_reg_index + 1) << 16);
				odm_write_1byte(p_dm_odm, 0x81, 0x80); /*RPTBUF ready*/

				PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, MacId = %d, ctrl_info_offset = 0x%x, mu_reg_index = %x\n", 
				__func__, pBeamformeeEntry->MacId, ctrl_info_offset, pBeamformeeEntry->mu_reg_index);
			}
#endif
		}
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "[%s]MU BFee Entry End\n", __func__);
	}
#endif // #if (MU_BEAMFORMING_SUPPORT == 1)
	RESTORE_INT(flags);
}


VOID
SetBeamformLeave8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	)
{
	
	struct dm_struct*	p_dm_odm = ODMPTR;
	struct _RT_BEAMFORMING_INFO* pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	struct _RT_BEAMFORMER_ENTRY*	pBeamformerEntry = NULL; 
	PRT_BEAMFORMING_ENTRY	pBeamformeeEntry = NULL;
	u4Byte					mu_reg[6] = {0x1684, 0x1686, 0x1688, 0x168a, 0x168c, 0x168e};
	u1Byte					h2c_content[6] = {0};

	if (Idx < BEAMFORMER_ENTRY_NUM)
		pBeamformerEntry = &pBeamformingInfo->BeamformerEntry[Idx];
	
	if (Idx < BEAMFORMEE_ENTRY_NUM)
		pBeamformeeEntry = &pBeamformingInfo->BeamformeeEntry[Idx];
	
	/*Clear P_AID of Beamformee*/
	/*Clear MAC address of Beamformer*/
	/*Clear Associated Bfmee Sel*/

	if(pBeamformerEntry && pBeamformerEntry->BeamformEntryCap == BEAMFORMING_CAP_NONE) { //eric-txbf
		pBeamformerEntry = &pBeamformingInfo->BeamformerEntry[Idx];
		
#if (MU_BEAMFORMING_SUPPORT == 1)		
		if (pBeamformerEntry->is_mu_ap) { /*MU BFer */
			/*set validity of MU STA0 and MU STA1*/
			if(pBeamformingInfo->beamformer_mu_cnt > 0)
				pBeamformingInfo->beamformer_mu_cnt -= 1;
			else
				panic_printk("%s(%d) Invalid beamformer_mu_cnt=%d\n", __FUNCTION__, __LINE__, pBeamformingInfo->beamformer_mu_cnt);
			
			pBeamformingInfo->RegMUTxCtrl &= 0xFFFFFFC0;
			GET_MACHALAPI_INTERFACE(priv)->halmac_mu_bfer_entry_del(priv->pHalmac_adapter);

			odm_memory_set(p_dm_odm, pBeamformerEntry->gid_valid, 0, 8);
			odm_memory_set(p_dm_odm, pBeamformerEntry->user_position, 0, 16);
			pBeamformerEntry->is_mu_ap = FALSE;
		} else 
#endif		
		{ /*SU BFer */
			if(pBeamformerEntry->su_reg_index != 0xFF) {
				if(pBeamformingInfo->beamformer_su_cnt > 0)
					pBeamformingInfo->beamformer_su_cnt -= 1;
				else
					panic_printk("%s(%d) Invalid beamformer_su_cnt=%d\n", __FUNCTION__, __LINE__, pBeamformingInfo->beamformer_su_cnt);

				GET_MACHALAPI_INTERFACE(priv)->halmac_su_bfer_entry_del(priv->pHalmac_adapter, pBeamformerEntry->su_reg_index);

				pBeamformingInfo->beamformer_su_reg_maping &= ~(BIT(pBeamformerEntry->su_reg_index));
				pBeamformerEntry->su_reg_index = 0xFF;
			}
		} 

		if (BFER_CNT(pBeamformingInfo) == 0)
			GET_MACHALAPI_INTERFACE(priv)->halmac_del_sounding(priv->pHalmac_adapter, HAL_BFEE);

	}
	if(pBeamformeeEntry && pBeamformeeEntry->BeamformEntryCap == BEAMFORMING_CAP_NONE) { //eric-txbf
#if (MU_BEAMFORMING_SUPPORT == 1)
		phydm_txbf_rfmode(p_dm_odm, pBeamformingInfo->beamformee_su_cnt, pBeamformingInfo->beamformee_mu_cnt);
#else
		phydm_txbf_rfmode(p_dm_odm, pBeamformingInfo->beamformee_su_cnt, 0);
#endif

#if (MU_BEAMFORMING_SUPPORT == 1)		
		if (pBeamformeeEntry->is_mu_sta == 0) 
#endif
		{ /*SU BFee*/
			if(pBeamformeeEntry->su_reg_index != 0xFF) { 
				if(pBeamformingInfo->beamformee_su_cnt > 0)
					pBeamformingInfo->beamformee_su_cnt -= 1;
				else
					panic_printk("%s(%d) Invalid beamformee_su_cnt=%d\n", __FUNCTION__, __LINE__, pBeamformingInfo->beamformee_su_cnt);

				GET_MACHALAPI_INTERFACE(priv)->halmac_su_bfee_entry_del(priv->pHalmac_adapter, pBeamformeeEntry->su_reg_index);
				
				pBeamformingInfo->beamformee_su_reg_maping &= ~(BIT(pBeamformeeEntry->su_reg_index));
				pBeamformeeEntry->su_reg_index = 0xFF;
			}
		} 
#if (MU_BEAMFORMING_SUPPORT == 1)		
		else { /*MU BFee */
			if(pBeamformeeEntry->mu_reg_index < MAX_NUM_BEAMFORMEE_MU ) {
				/*Disable sending NDPA & BF-rpt-poll to this BFee*/
				if(pBeamformingInfo->beamformee_mu_cnt > 0)
					pBeamformingInfo->beamformee_mu_cnt -= 1;
				else
					panic_printk("%s(%d) Invalid beamformee_mu_cnt=%d\n", __FUNCTION__, __LINE__, pBeamformingInfo->beamformee_mu_cnt);
				
				/*set validity of MU STA*/
				pBeamformingInfo->RegMUTxCtrl &= ~(BIT(pBeamformeeEntry->mu_reg_index));

				GET_MACHALAPI_INTERFACE(priv)->halmac_mu_bfee_entry_del(priv->pHalmac_adapter, pBeamformeeEntry->mu_reg_index + 2);
				
				h2c_content[0] = 2;
				h2c_content[1] = pBeamformeeEntry->mu_reg_index;
				odm_fill_h2c_cmd(p_dm_odm, PHYDM_H2C_MU, 2, h2c_content);

				pBeamformeeEntry->is_mu_sta = FALSE;				
				pBeamformingInfo->beamformee_mu_reg_maping &= ~(BIT(pBeamformeeEntry->mu_reg_index));
				pBeamformeeEntry->mu_reg_index = 0xFF;
			} 
		}
#endif
		
		if (BFEE_CNT(pBeamformingInfo) == 0)
			GET_MACHALAPI_INTERFACE(priv)->halmac_del_sounding(priv->pHalmac_adapter, HAL_BFER);
	}
}

void
Beamforming_dym_disable_bf_coeff_8814B(
	struct rtl8192cd_priv *priv,
	u1Byte				   enable
)
{
	if(enable) {
		RTL_W16(0x1910, 0x200);
		RTL_W16(0x9e8, RTL_R16(0x9e8) | BIT12);
	} else {
		RTL_W16(0x1910, 0);
		RTL_W16(0x9e8, RTL_R16(0x9e8) & ~BIT12);
	}
}

/***********SU & MU BFee Entry Only when souding done****************/
VOID
SetBeamformStatus8814B(
	struct rtl8192cd_priv *priv,
	IN u1Byte				Idx
	)
{
	struct dm_struct*	p_dm_odm = ODMPTR;
	u2Byte					BeamCtrlVal, tmpVal;
	u4Byte					BeamCtrlReg;
	struct _RT_BEAMFORMING_INFO* pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	PRT_SOUNDING_INFOV2 pSoundingInfo = &(pBeamformingInfo->SoundingInfoV2);
	PRT_BEAMFORMING_ENTRY	pBeamformEntry;
	u16 bitmap;
	u8 idx, gid, i;
	u8 id1, id0;
#if (MU_BEAMFORMING_SUPPORT == 1)	
	u32 gid_valid[6] = {0};
	u32 user_position_lsb[6] = {0};
	u32 user_position_msb[6] = {0};
	u8  bSnding;
#endif	
	u32 value32;
	u16 value16;
	BOOLEAN is_sounding_success[4] = {FALSE};
	u8		snd_result = 0, isApplyMU = 0;

	if (Idx < BEAMFORMEE_ENTRY_NUM)
		pBeamformEntry = &pBeamformingInfo->BeamformeeEntry[Idx];
	else
		return;

	/*SU sounding done */
	if(pSoundingInfo->State == SOUNDING_STATE_SU_SOUNDDOWN) {
		
		BeamCtrlVal = pBeamformEntry->P_AID;

		PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, BeamformEntry.BeamformEntryState = %d\n", __func__, pBeamformEntry->BeamformEntryState);

		if (pBeamformEntry->su_reg_index == 0) {
			BeamCtrlReg = REG_TXBF_CTRL_8814B;
		} else {
			BeamCtrlReg = REG_TXBF_CTRL_8814B+2;
			BeamCtrlVal |= BIT12|BIT14|BIT15;
		}
			
		if(pBeamformEntry->pSTA && pBeamformEntry->pSTA->error_csi == 1 && pBeamformEntry->pSTA->current_tx_rate >= _NSS2_MCS0_RATE_ && (priv->pshare->rf_ft_var.applyVmatrix)) {
			PHYDM_DBG(p_dm_odm, DBG_TXBF, "2SS Don't Apply Vmatrix");
			BeamCtrlVal &= ~(BIT9|BIT10|BIT11);
		}
#ifdef CONFIG_VERIWAVE_MU_CHECK		
		else if(pBeamformEntry->pSTA && pBeamformEntry->pSTA->isVeriwaveSTA && !pBeamformEntry->is_mu_sta) {
			BeamCtrlVal &= ~(BIT9|BIT10|BIT11); 
		}	
#endif
		else if ((pBeamformEntry->BeamformEntryState == BEAMFORMING_ENTRY_STATE_PROGRESSED) && (priv->pshare->rf_ft_var.applyVmatrix)) {
			if (pBeamformEntry->BW == CHANNEL_WIDTH_20)
				BeamCtrlVal |= BIT9;
			else if (pBeamformEntry->BW == CHANNEL_WIDTH_40)
				BeamCtrlVal |= (BIT9|BIT10);
			else if (pBeamformEntry->BW == CHANNEL_WIDTH_80)
				BeamCtrlVal |= (BIT9|BIT10|BIT11);		
		} else {
			PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, Don't apply Vmatrix", __func__);
			BeamCtrlVal &= ~(BIT9|BIT10|BIT11);
		}

		odm_write_2byte(p_dm_odm, BeamCtrlReg, BeamCtrlVal);
		/*disable NDP packet use beamforming */
		tmpVal = odm_read_2byte(p_dm_odm, REG_TXBF_CTRL_8814B);
		odm_write_2byte(p_dm_odm, REG_TXBF_CTRL_8814B, tmpVal|BIT15);
	} 
#if (MU_BEAMFORMING_SUPPORT == 1)	
	else {
		PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, MU Sounding Done\n", __func__);
		/*MU sounding done */
		if (1){//(pBeamformEntry->BeamformEntryState == BEAMFORMING_ENTRY_STATE_PROGRESSED) {
			//PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, BEAMFORMING_ENTRY_STATE_PROGRESSED\n", __func__);

			value16 = odm_read_2byte(p_dm_odm, 0x1684);
			is_sounding_success[0] = (value16 & BIT10)?1:0;
			value16 = odm_read_2byte(p_dm_odm, 0x1686);
			is_sounding_success[1] = (value16 & BIT10)?1:0;
			value16 = odm_read_2byte(p_dm_odm, 0x1688);
			is_sounding_success[2] = (value16 & BIT10)?1:0;
			value16 = odm_read_2byte(p_dm_odm, 0x168A);
			is_sounding_success[3] = (value16 & BIT10)?1:0;

#ifdef CONFIG_VERIWAVE_MU_CHECK		
			for(Idx = 0; Idx < BEAMFORMEE_ENTRY_NUM; Idx++)
			{		
				pBeamformEntry = &(pBeamformingInfo->BeamformeeEntry[Idx]);
				if(pBeamformEntry->pSTA && pBeamformEntry->pSTA->isVeriwaveInValidSTA) {					
					Beamforming_set_csi_data(priv, pBeamformEntry->pSTA->isVeriwaveInValidSTA - 1, pBeamformEntry->mu_reg_index);						
					is_sounding_success[pBeamformEntry->mu_reg_index] = 1;
				}
			}
#endif
			snd_result = is_sounding_success[0];
			for(i=1;i<4;i++) {
				snd_result |= (is_sounding_success[i] << i);
			}

			isApplyMU = 0;
			for(i = 0; i < BEAMFORMEE_ENTRY_NUM; i++) {				
				pBeamformEntry = &(pBeamformingInfo->BeamformeeEntry[i]);
				if( pBeamformEntry->bUsed && pBeamformEntry->is_mu_sta && pBeamformEntry->pSTA && pBeamformEntry->mu_reg_index < MAX_NUM_BEAMFORMEE_MU) {
						isApplyMU |= (pBeamformEntry->pSTA->isRssiApplyMU << pBeamformEntry->mu_reg_index);
				}
			}
			pBeamformingInfo->RegMUTxCtrl &= 0xFFFFFFC0;
			pBeamformingInfo->RegMUTxCtrl |= (0x3F & snd_result & isApplyMU);
				
			PHYDM_DBG(p_dm_odm, DBG_TXBF, "@%s, is_sounding_success STA1:%d,  STA2:%d, STA3:%d, STA4:%d\n", 
				__func__, is_sounding_success[0], is_sounding_success[1] , is_sounding_success[2] , is_sounding_success[3]);

			bSnding = 0;
			for(i = 0; i < BEAMFORMEE_ENTRY_NUM; i++) {				
				pBeamformEntry = &(pBeamformingInfo->BeamformeeEntry[i]);
				if( pBeamformEntry->bUsed && pBeamformEntry->is_mu_sta && pBeamformEntry->pSTA && pBeamformEntry->mu_reg_index < MAX_NUM_BEAMFORMEE_MU) {
					if(pBeamformEntry->pSTA->isSendNDPA) {
						bSnding = 1;
						if(is_sounding_success[pBeamformEntry->mu_reg_index])
							priv->pshare->rf_ft_var.mu_ok[pBeamformEntry->mu_reg_index] ++;
						else {							
							priv->pshare->rf_ft_var.mu_fail[pBeamformEntry->mu_reg_index] ++;
						}
					}
				}
			}
			
			{
				u2Byte ptcl_gen_mu_cnt, wmac_tx_mu_cnt, wmac_rx_mu_ba_ok_cnt, wmac_tx_bar_cnt, wmac_rx_sta2_ba_ok_cnt, mu2su_tx_cnt; 

				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 0);
				ptcl_gen_mu_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);
				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 1);
				wmac_tx_mu_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);
				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 2);
				wmac_rx_mu_ba_ok_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);
				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 3);
				wmac_tx_bar_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);
				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 4);
				wmac_rx_sta2_ba_ok_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);
				odm_set_bb_reg(p_dm_odm, 0x14D0, 0xF0000, 5);
				mu2su_tx_cnt = odm_get_bb_reg(p_dm_odm, 0x14D0, 0xFFFF);

				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, ptcl_gen_mu_cnt = %d\n",  __func__, ptcl_gen_mu_cnt);
				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, wmac_tx_mu_cnt = %d\n",  __func__, wmac_tx_mu_cnt);
				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, wmac_rx_mu_ba_ok_cnt = %d\n",  __func__, wmac_rx_mu_ba_ok_cnt);
				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, wmac_tx_bar_cnt = %d\n",  __func__, wmac_tx_bar_cnt);
				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, wmac_rx_sta2_ba_ok_cnt = %d\n",  __func__, wmac_rx_sta2_ba_ok_cnt);
				PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s, mu2su_tx_cnt = %d\n\n\n",  __func__, mu2su_tx_cnt);
				
				odm_set_bb_reg(p_dm_odm, 0x14D0, BIT20, 1); //reset MU counter
			}	
#if 0			
			value32 = odm_get_bb_reg(p_dm_odm, 0xF4C, 0xFFFF0000);
			//odm_set_bb_reg(p_dm_odm, 0x19E0, bMaskHWord, 0xFFFF);/*Let MAC ignore bitmap*/
			
			bitmap = (u16)(value32 & 0x7FFF);

			if(bSnding) {
				if(bitmap)
					priv->pshare->rf_ft_var.mu_BB_ok++;
				else
					priv->pshare->rf_ft_var.mu_BB_fail++;
			}

			beamform_MUGrouping(priv, bitmap, priv->pshare->rf_ft_var.muPairResult);

		
			for (idx = 0; idx < 15; idx++) {
				if (idx < 5) {/*bit0~4*/
					id0 = 0;
					id1 = (u8)(idx + 1);
				} else if (idx < 9) { /*bit5~8*/
					id0 = 1;
					id1 = (u8)(idx - 3);
				} else if (idx < 12) { /*bit9~11*/
					id0 = 2;
					id1 = (u8)(idx - 6);
				} else if (idx < 14) { /*bit12~13*/	
					id0 = 3;
					id1 = (u8)(idx - 8);
				} else { /*bit14*/
					id0 = 4;
					id1 = (u8)(idx - 9);
				}
				
				if(priv->pshare->rf_ft_var.muPairResult[id0] != id1) // unmark nonpair bitmap
					continue;
				
				if (bitmap & BIT(idx)) {
					/*Pair 1*/
					gid = (idx << 1) + 1;
					gid_valid[id0] |= (BIT(gid));
					gid_valid[id1] |= (BIT(gid));
					/*Pair 2*/
					gid += 1;
					gid_valid[id0] |= (BIT(gid));
					gid_valid[id1] |= (BIT(gid));
				} else {
					/*Pair 1*/
					gid = (idx << 1) + 1;
					gid_valid[id0] &= ~(BIT(gid));
					gid_valid[id1] &= ~(BIT(gid));
					/*Pair 2*/
					gid += 1;
					gid_valid[id0] &= ~(BIT(gid));
					gid_valid[id1] &= ~(BIT(gid));
				}
			}

			for (i = 0; i < BEAMFORMEE_ENTRY_NUM; i++) {
				pBeamformEntry = &pBeamformingInfo->BeamformeeEntry[i];
				if (pBeamformEntry->bUsed && pBeamformEntry->is_mu_sta && (pBeamformEntry->mu_reg_index < MAX_NUM_BEAMFORMEE_MU)) {
					value32 = gid_valid[pBeamformEntry->mu_reg_index];
					for (idx = 0; idx < 4; idx++) {
						pBeamformEntry->gid_valid[idx] = (u8)(value32 & 0xFF);
						value32 = (value32 >> 8);
					}
				}
			}

			for (idx = 0; idx < 6; idx++) {
				pBeamformingInfo->RegMUTxCtrl &= ~(BIT8|BIT9|BIT10);
				pBeamformingInfo->RegMUTxCtrl |= ((idx<<8)&(BIT8|BIT9|BIT10));
				odm_write_4byte(p_dm_odm, 0x14c0, pBeamformingInfo->RegMUTxCtrl);
				odm_set_mac_reg(p_dm_odm, 0x14C4, bMaskDWord, gid_valid[idx]); /*set MU STA gid valid table*/
			}

			/*Enable TxMU PPDU*/
#if 1 //eric-mu enable mu tx
			if (priv->pshare->rf_ft_var.applyVmatrix)
				pBeamformingInfo->RegMUTxCtrl |= BIT7;
			else
				pBeamformingInfo->RegMUTxCtrl &= ~ (BIT7 | 0x3F);
#else
			pBeamformingInfo->RegMUTxCtrl |= BIT7;
#endif

			odm_write_4byte(p_dm_odm, 0x14c0, pBeamformingInfo->RegMUTxCtrl);
#endif
		}
	}
#if 0
	else {
		if(pSoundingInfo->State == SOUNDING_STATE_MU_SOUNDDOWN) {
			if (pBeamformingInfo->beamformee_mu_cnt >= 2) {
				u1Byte buf[8] = {
					0x00, 0x00, 0x00, 0x00,
					0x20, 0x00, 0x20, 0x00 
				};
				
				C2HTxBeamformingGroupDoneHandler88XX(priv, buf, sizeof(buf));
			}
		}
	}
#endif
#endif
}

VOID Beamforming_NDPARate_8814B(
	struct rtl8192cd_priv *priv,
	BOOLEAN		Mode,
	u1Byte		BW,
	u1Byte		Rate
	)
{
	u2Byte	NDPARate = Rate;

	if (NDPARate == 0) {
		if(priv->pshare->rssi_min > 30) // link RSSI > 30%
			NDPARate = 0x8;				//MGN_24M
		else
			NDPARate = 0x4;				//MGN_6M
	}

	RTL_W8(REG_NDPA_RATE, NDPARate);

}

/*Only used for MU BFer Entry when get GID management frame (self is as MU STA)*/
VOID
HalTxbf8814B_ConfigGtab(
	struct rtl8192cd_priv *priv
	)
{
	struct dm_struct*	p_dm_odm = ODMPTR;
	struct _RT_BEAMFORMING_INFO* pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	struct _RT_BEAMFORMER_ENTRY*	pBeamformerEntry = NULL;
	u4Byte		gid_valid = 0, user_position_l = 0, user_position_h = 0, i;
	struct halmac_cfg_mumimo_para mu_para, *para = &mu_para;

	if (pBeamformingInfo->mu_ap_index < BEAMFORMER_ENTRY_NUM)
		pBeamformerEntry = &pBeamformingInfo->BeamformerEntry[pBeamformingInfo->mu_ap_index];
	else
		return;

	PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s==>\n", __func__);

	/*For GID 0~31*/
	for (i = 0; i < 4; i++)
		gid_valid |= (pBeamformerEntry->gid_valid[i] << (i<<3));
	for (i = 0; i < 8; i++) {
		if (i < 4)
			user_position_l |= (pBeamformerEntry->user_position[i] << (i << 3));
		else
			user_position_h |= (pBeamformerEntry->user_position[i] << ((i - 4)<<3));
	}
	para->given_gid_tab[0] = gid_valid;
	para->given_user_pos[0] = user_position_l;
	para->given_user_pos[1] = user_position_h;

	PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s: STA0: gid_valid = 0x%x, user_position_l = 0x%x, user_position_h = 0x%x\n",
		__func__, gid_valid, user_position_l, user_position_h);

	gid_valid = 0;
	user_position_l = 0;
	user_position_h = 0;

	/*For GID 32~64*/
	for (i = 4; i < 8; i++)
		gid_valid |= (pBeamformerEntry->gid_valid[i] << ((i - 4)<<3));
	for (i = 8; i < 16; i++) {
		if (i < 12)
			user_position_l |= (pBeamformerEntry->user_position[i] << ((i - 8) << 3));
		else
			user_position_h |= (pBeamformerEntry->user_position[i] << ((i - 12) << 3));
	}
	para->given_gid_tab[1] = gid_valid;
	para->given_user_pos[2] = user_position_l;
	para->given_user_pos[3] = user_position_h;

	PHYDM_DBG(p_dm_odm, DBG_TXBF, "%s: STA1: gid_valid = 0x%x, user_position_l = 0x%x, user_position_h = 0x%x\n",
		__func__, gid_valid, user_position_l, user_position_h);

	para->role = HAL_BFEE;
	GET_MACHALAPI_INTERFACE(priv)->halmac_cfg_mumimo(priv->pHalmac_adapter, para);
}



#if 0
/*This function translate the bitmap to GTAB*/
VOID
haltxbf8814b_gtab_translation(
	IN PDM_ODM_T			pDM_Odm
) 
{
	u8 idx, gid;
	u8 id1, id0;
	u32 gid_valid[6] = {0};
	u32 user_position_lsb[6] = {0};
	u32 user_position_msb[6] = {0};
	
	for (idx = 0; idx < 15; idx++) {
		if (idx < 5) {/*bit0~4*/
			id0 = 0;
			id1 = (u8)(idx + 1);
		} else if (idx < 9) { /*bit5~8*/
			id0 = 1;
			id1 = (u8)(idx - 3);
		} else if (idx < 12) { /*bit9~11*/
			id0 = 2;
			id1 = (u8)(idx - 6);
		} else if (idx < 14) { /*bit12~13*/	
			id0 = 3;
			id1 = (u8)(idx - 8);
		} else { /*bit14*/
			id0 = 4;
			id1 = (u8)(idx - 9);
		}

		/*Pair 1*/
		gid = (idx << 1) + 1;
		gid_valid[id0] |= (1 << gid);
		gid_valid[id1] |= (1 << gid);
		if (gid < 16) {
			/*user_position_lsb[id0] |= (0 << (gid << 1));*/
			user_position_lsb[id1] |= (1 << (gid << 1));
		} else {
			/*user_position_msb[id0] |= (0 << ((gid - 16) << 1));*/
			user_position_msb[id1] |= (1 << ((gid - 16) << 1));
		}
		
		/*Pair 2*/
		gid += 1;
		gid_valid[id0] |= (1 << gid);
		gid_valid[id1] |= (1 << gid);
		if (gid < 16) {
			user_position_lsb[id0] |= (1 << (gid << 1));
			/*user_position_lsb[id1] |= (0 << (gid << 1));*/
		} else {
			user_position_msb[id0] |= (1 << ((gid - 16) << 1));
			/*user_position_msb[id1] |= (0 << ((gid - 16) << 1));*/
		}

	}


	for (idx = 0; idx < 6; idx++) {
		/*DbgPrint("gid_valid[%d] = 0x%x\n", idx, gid_valid[idx]);
		DbgPrint("user_position[%d] = 0x%x   %x\n", idx, user_position_msb[idx], user_position_lsb[idx]);*/
	}
}
#endif

VOID
HalTxbf8814B_FwTxBF(
	IN PVOID			pDM_VOID,
	IN	u1Byte				Idx
	)
{
#if 0
	PRT_BEAMFORMING_INFO 	pBeamInfo = GET_BEAMFORM_INFO(Adapter);
	PRT_BEAMFORMEE_ENTRY	pBeamEntry = pBeamInfo->BeamformeeEntry+Idx;

	if (pBeamEntry->BeamformEntryState == BEAMFORMING_ENTRY_STATE_PROGRESSING)
		halTxbf8814B_DownloadNDPA(Adapter, Idx);

	halTxbf8814B_FwTxBFCmd(Adapter);
#endif
}

VOID
C2HTxBeamformingHandler_8814B(
	struct rtl8192cd_priv *priv,
		pu1Byte			CmdBuf,
		u1Byte			CmdLen
)
{
	u1Byte 	status = CmdBuf[0] & BIT0;

	PHYDM_DBG(ODMPTR, DBG_TXBF, "%s =>\n", __FUNCTION__);
	Beamform_SoundingDown(priv, status);
}

#endif 


